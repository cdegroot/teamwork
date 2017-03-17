defmodule GoogleAuth do
  @moduledoc """
  A quick and dirty module to do Google OAuth2 using the
  device profile - that seems to be a reasonable and portable
  way to authenticate for a CLI.
  """
  require Logger
  use GenServer

  defmodule State, do: defstruct [:client_id, :client_secret, :device_code,
                                  :access_token, :refresh_token, :refresh_time,
                                 :expiry_time, :state_file]

  def start_link(json_file) do
    # Before we start the async stuff, let's start the login process
    initial_state = start_user_login(json_file)
    GenServer.start_link(__MODULE__, initial_state, name: __MODULE__)
  end

  def get_token() do
    # Antipattern alert!
    GenServer.call(__MODULE__, :get_token)
  end

  def wait_for_token() do
    token = GenServer.call(__MODULE__, :get_token)
    if is_nil(token) do
      Process.sleep(1000)
      wait_for_token()
    else
      token
    end
  end

  defp start_user_login(json_file) do
    state_file = "#{json_file}.state"
    if File.exists?(state_file) do
      # Restore from state
      {:ok, data} = File.read(state_file)
      old = :erlang.binary_to_term(data)
      # Add missing keys
      state = Enum.reduce(Map.keys(State.__struct__), old, fn(k, old) ->
        Map.put_new(old, k, nil)
      end)
      # Might have been moved, etc...
      %State{state | state_file: state_file}
    else
      # Start a new auth process
      {:ok, json} = File.read(json_file)
      {:ok, client} = Poison.Parser.parse(json)
      client_id = client["installed"]["client_id"]
      client_secret = client["installed"]["client_secret"]
      body = "client_id=#{client_id}&scope=email%20profile%20https://www.googleapis.com/auth/calendar.readonly"
      {:ok, result} = HTTPoison.post("https://accounts.google.com/o/oauth2/device/code", body, [{"Content-Type", "application/x-www-form-urlencoded"}])
      {:ok, response_body} = Poison.Parser.parse(result.body)
      IO.puts("Please go to this URL:\n\n#{response_body["verification_url"]}\n\nEnter this verification code:\n\n#{response_body["user_code"]}\n\nAfter login.\n")
      device_code = response_body["device_code"]
      %State{client_id: client_id, client_secret: client_secret,
             device_code: device_code, state_file: state_file}
    end
  end

  # GenServer stuff

  def init(initial_state) do
    if is_nil(initial_state.refresh_token) do
      Process.send_after(self(), :poll_for_client_auth, 1000)
    else
      send(self(), :refresh_auth)
    end
    {:ok, initial_state}
  end

  def handle_call(:get_token, _from, state) do
    token = if is_nil(state.access_token) do
      nil
    else
      "Bearer #{state.access_token}"
    end
    {:reply, token, state}
  end

  def handle_info(:poll_for_client_auth, state) do
    case HTTPoison.post("https://www.googleapis.com/oauth2/v4/token", "client_id=#{state.client_id}&client_secret=#{state.client_secret}&code=#{state.device_code}&grant_type=http://oauth.net/grant_type/device/1.0", [{"Content-Type", "application/x-www-form-urlencoded"}]) do
      {:ok, auth_response} ->
        {:ok, auth} = Poison.Parser.parse(auth_response.body)
        if Map.has_key?(auth, "access_token") do
          new_state = state
          |> parse_auth(auth)
          |> setup_refresh
          |> dump_state
          {:noreply, new_state}
        else
          Logger.info("Didn't get an auth from poll, retrying...")
          Logger.debug("auth: #{inspect auth}")
          Process.send_after(self(), :poll_for_client_auth, 5000)
          {:noreply, state}
        end
      res ->
        Logger.info("Got non-ok result from poll, retrying...")
        Logger.debug("result: #{inspect res}")
        Process.send_after(self(), :poll_for_client_auth, 5000)
        {:noreply, state}
    end
  end

  def handle_info(:refresh_auth, state) do
    case HTTPoison.post("https://www.googleapis.com/oauth2/v4/token", "client_id=#{state.client_id}&client_secret=#{state.client_secret}&refresh_token=#{state.refresh_token}&grant_type=refresh_token", [{"Content-Type", "application/x-www-form-urlencoded"}]) do
      {:ok, auth_response} ->
        {:ok, auth} = Poison.Parser.parse(auth_response.body)
        if Map.has_key?(auth, "access_token") do
          new_state = state
          |> parse_refresh(auth)
          |> setup_refresh
          |> dump_state
          {:noreply, new_state}
        else
          Logger.info("Didn't get an auth from refresh, retrying...")
          Logger.debug("auth: #{inspect auth}")
          Process.send_after(self(), :refresh_auth, 5000)
          {:noreply, state}
        end
      res ->
        Logger.info("Got non-ok result from refresh, retrying...")
        Logger.debug("result: #{inspect res}")
        Process.send_after(self(), :refresh_auth, 5000)
        {:noreply, state}
    end
  end

  defp parse_auth(state, auth) do
    %State{state | access_token: auth["access_token"],
           refresh_token: auth["refresh_token"],
           refresh_time: auth["expires_in"]}
  end

  defp parse_refresh(state, auth) do
    %State{state | access_token: auth["access_token"],
           refresh_time: auth["expires_in"]}
  end

  defp setup_refresh(state) do
    # We have a refresh time in delta seconds. Subtract a minute as buffer and schedule
    # a refresh.
    refresh_in = state.refresh_time - 60
    expiry_time = (DateTime.utc_now() |> DateTime.to_unix) + state.refresh_time
    Process.send_after(self(), :refresh_auth, refresh_in * 1000)
    %State{state | expiry_time: expiry_time}
  end

  defp dump_state(state) do
    data = :erlang.term_to_binary(state)
    File.write(state.state_file, data)
    state
  end
end
