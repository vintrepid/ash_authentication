defmodule AshAuthentication.AssentCompatibilityTest do
  use ExUnit.Case, async: true
  alias AshAuthentication.AssentCompatibility

  test "Assent 0.4 receives atoms while 0.3 retains string configuration" do
    assert AssentCompatibility.client_authentication_method("client_secret_post", "0.4.0") ==
             :client_secret_post

    assert AssentCompatibility.client_authentication_method(:client_secret_post, "0.3.2") ==
             "client_secret_post"

    assert AssentCompatibility.client_authentication_method(nil, "0.4.0") == nil

    assert AssentCompatibility.client_authentication_method("invalid-method", "0.4.0") ==
             "invalid-method"
  end
end
