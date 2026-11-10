defmodule AshAuthentication.AssentOAuthConfigurationTest do
  use DataCase, async: true
  import Plug.Test
  alias AshAuthentication.{Info, Strategy.OAuth2.Plug}

  defmodule CapturingStrategy do
    @behaviour Assent.Strategy
    def authorize_url(config) do
      send(self(), {:client_method, Keyword.get(config, :client_authentication_method)})
      {:ok, %{url: "https://example.com/authorize", session_params: %{state: "test-state"}}}
    end

    def callback(_config, _params), do: {:error, :unused}
  end

  test "OAuth request passes the method in the representation supported by installed Assent" do
    {:ok, strategy} = Info.strategy(Example.User, :oauth2)

    strategy = %{
      strategy
      | assent_strategy: CapturingStrategy,
        client_authentication_method: "client_secret_post"
    }

    conn = :get |> conn("/", %{}) |> SessionPipeline.call([]) |> Plug.request(strategy)
    assert conn.status == 302

    expected =
      if Version.match?(to_string(Application.spec(:assent, :vsn)), ">= 0.4.0"),
        do: :client_secret_post,
        else: "client_secret_post"

    assert_received {:client_method, ^expected}
  end
end
