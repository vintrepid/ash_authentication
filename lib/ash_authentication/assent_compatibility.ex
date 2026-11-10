defmodule AshAuthentication.AssentCompatibility do
  @moduledoc false

  @methods %{
    "client_secret_basic" => :client_secret_basic,
    "client_secret_post" => :client_secret_post,
    "client_secret_jwt" => :client_secret_jwt,
    "private_key_jwt" => :private_key_jwt,
    "none" => :none
  }

  def client_authentication_method(method) do
    version = Application.spec(:assent, :vsn) |> to_string()
    client_authentication_method(method, version)
  end

  def client_authentication_method(nil, _version), do: nil

  def client_authentication_method(method, version) do
    if Version.match?(version, ">= 0.4.0") do
      if is_binary(method), do: Map.get(@methods, method, method), else: method
    else
      to_string(method)
    end
  end
end
