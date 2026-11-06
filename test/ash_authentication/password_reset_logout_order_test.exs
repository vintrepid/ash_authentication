defmodule AshAuthentication.PasswordResetLogoutOrderTest do
  use DataCase, async: false

  alias AshAuthentication.{Info, Jwt, Strategy, Strategy.Password, TokenResource}

  test "reset consumes its token before logging out sessions and cannot be replayed" do
    user = build_user_with_token_required()
    strategy = Info.strategy!(Example.UserWithTokenRequired, :password)
    {:ok, _session, %{"jti" => session_jti}} = Jwt.token_for_user(user)
    {:ok, reset_token} = Password.reset_token_for(strategy, user)

    params = %{
      "reset_token" => reset_token,
      "password" => "updated-password",
      "password_confirmation" => "updated-password"
    }

    assert {:ok, _user} = Strategy.action(strategy, :reset, params)
    assert TokenResource.jti_revoked?(Example.Token, session_jti)
    assert TokenResource.token_revoked?(Example.Token, reset_token)
    assert {:error, _} = Strategy.action(strategy, :reset, params)
  end
end
