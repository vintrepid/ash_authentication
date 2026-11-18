# SPDX-FileCopyrightText: 2026 Vintrepid
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.ForkSecurityRegressionTest do
  @moduledoc false
  use DataCase, async: true
  use Mimic

  alias AshAuthentication.{Info, Jwt, Plug.Helpers, TokenResource.Actions}
  alias AshAuthentication.Strategy.{MagicLink, Password}
  alias Plug.Conn
  require Ash.Query

  import ExUnit.CaptureLog

  setup do
    {:ok, conn: SessionPipeline.call(Plug.Test.conn(:get, "/"), [])}
  end

  test "a captured JTI session stops authenticating after logout with token presence disabled", %{
    conn: conn
  } do
    user = build_user()
    assert Info.authentication_session_identifier!(Example.User) == :jti
    refute Info.authentication_tokens_require_token_presence_for_authentication?(Example.User)

    captured = Helpers.store_in_session(conn, user)

    assert Helpers.retrieve_from_session(captured, :ash_authentication).assigns.current_user.id ==
             user.id

    {:ok, %{"jti" => jti}} = Jwt.peek(user.__metadata__.token)
    Helpers.revoke_session_tokens(captured, :ash_authentication)

    assert Actions.jti_revoked?(Example.Token, jti)
    refute Helpers.retrieve_from_session(captured, :ash_authentication).assigns.current_user

    session = %{"user" => Conn.get_session(captured, "user")}

    refute Helpers.assign_new_resources(%{}, session, &Map.put_new_lazy/3,
             otp_app: :ash_authentication
           )[:current_user]
  end

  test "an unstored JTI session is also rejected after its revocation", %{conn: conn} do
    resource = Example.UserWithSelectiveStrategyIncludes
    refute Info.authentication_tokens_store_all_tokens?(resource)
    refute Info.authentication_tokens_require_token_presence_for_authentication?(resource)

    user =
      Ash.create!(
        resource,
        %{
          email: "unstored_#{System.unique_integer([:positive])}@example.com",
          password: password(),
          password_confirmation: password()
        },
        action: :register_with_password
      )

    captured = Helpers.store_in_session(conn, user)
    loaded = Helpers.retrieve_from_session(captured, :ash_authentication)
    assert loaded.assigns.current_user_with_selective_strategy_includes.id == user.id

    Helpers.revoke_session_tokens(captured, :ash_authentication)

    refute Helpers.retrieve_from_session(captured, :ash_authentication).assigns[
             :current_user_with_selective_strategy_includes
           ]
  end

  test "legacy explicit revocation modes retain exclusivity for stored and unstored tokens" do
    for stored? <- [true, false] do
      user = build_user()
      token = user.__metadata__.token
      {:ok, %{"jti" => jti}} = Jwt.peek(token)

      unless stored? do
        Example.Token
        |> Ash.Query.filter(jti == ^jti)
        |> Ash.bulk_destroy!(:destroy, %{}, authorize?: false)
      end

      assert :ok = Actions.revoke(Example.Token, token, store_all_tokens?: stored?)

      assert {:error, %AshAuthentication.Errors.InvalidToken{type: :revocation}} =
               Actions.revoke(Example.Token, token, store_all_tokens?: stored?)
    end
  end

  test "expired and wrong-purpose JWT sessions remain rejected", %{conn: conn} do
    user = build_user_with_token_required()
    expired_at = DateTime.utc_now() |> DateTime.to_unix() |> Kernel.-(60)
    {:ok, expired_token, _} = Jwt.token_for_user(user, %{"exp" => expired_at})
    strategy = Info.strategy!(user.__struct__, :password)
    {:ok, reset_token} = Password.reset_token_for(strategy, user)

    for token <- [expired_token, reset_token] do
      loaded =
        conn
        |> Conn.put_session("user_with_token_required_token", token)
        |> Helpers.retrieve_from_session(:ash_authentication)

      refute loaded.assigns.current_user_with_token_required
    end
  end

  test "legacy JTI revocation is exclusive while explicit upstream logout remains idempotent" do
    user = build_user()
    token = user.__metadata__.token
    {:ok, %{"jti" => jti}} = Jwt.peek(token)
    subject = AshAuthentication.user_to_subject(user)

    assert :ok = Actions.revoke_jti(Example.Token, jti, subject, store_all_tokens?: true)

    assert {:error, %AshAuthentication.Errors.InvalidToken{type: :revocation}} =
             Actions.revoke_jti(Example.Token, jti, subject, store_all_tokens?: true)

    for _ <- 1..2 do
      assert :ok =
               Actions.revoke(Example.Token, token, store_all_tokens?: true, single_use?: false)
    end
  end

  test "magic-link read returns a native error if the session token cannot be generated" do
    user = build_user()
    strategy = Info.strategy!(Example.User, :magic_link)
    {:ok, token} = MagicLink.request_token_for(strategy, user)

    Mimic.expect(Jwt, :token_for_user, fn _, _, _ -> :error end)

    assert {:error, _} =
             MagicLink.Actions.sign_in(strategy, %{token: token}, [])

    assert Actions.token_revoked?(Example.Token, token)
  end

  test "magic-link registration returns a native error if the session token cannot be generated" do
    strategy = Info.strategy!(Example.UserWithRegisterMagicLink, :magic_link)
    email = "jwt_failure_#{System.unique_integer([:positive])}@example.com"

    log =
      capture_log(fn ->
        MagicLink.Actions.request(strategy, %{email: email}, [])
      end)

    token =
      log
      |> String.split("Magic link request for #{email}, token \"", parts: 2)
      |> Enum.at(1)
      |> String.split("\"", parts: 2)
      |> Enum.at(0)

    Mimic.expect(Jwt, :token_for_user, fn _, _, _ -> :error end)

    assert {:error, _} =
             MagicLink.Actions.sign_in(strategy, %{token: token}, [])

    assert Actions.token_revoked?(Example.Token, token)
  end
end
