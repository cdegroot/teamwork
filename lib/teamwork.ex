defmodule Teamwork do
  use Application
  def start(_, _) do
    GoogleAuth.start_link("/Users/cees/.teamwork_client_id.json")
  end
end
