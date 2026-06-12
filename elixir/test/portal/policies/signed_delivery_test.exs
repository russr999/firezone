defmodule Portal.Policies.SignedDeliveryTest do
  use ExUnit.Case, async: true

  alias Portal.Account
  alias Portal.Crypto
  alias Portal.Policies.SignedDelivery

  defp account_with_keypair do
    {public_key, private_key} = Crypto.generate_signing_keypair()
    %Account{signing_public_key: public_key, signing_private_key: private_key}
  end

  describe "sign_resources/2 and verify_resources/3" do
    test "a signed payload verifies against the account public key" do
      account = account_with_keypair()
      resources = [%{"id" => "r1", "type" => "dns"}, %{"id" => "r2", "type" => "cidr"}]

      signature = SignedDelivery.sign_resources(account, resources)
      assert is_binary(signature)
      assert SignedDelivery.verify_resources(account, resources, signature)
    end

    test "verification fails when the payload is tampered with" do
      account = account_with_keypair()
      resources = [%{"id" => "r1"}]
      signature = SignedDelivery.sign_resources(account, resources)

      tampered = [%{"id" => "r1-evil"}]
      refute SignedDelivery.verify_resources(account, tampered, signature)
    end

    test "returns nil signature for an account without a keypair" do
      account = %Account{signing_public_key: nil, signing_private_key: nil}
      assert SignedDelivery.sign_resources(account, [%{"id" => "r1"}]) == nil
      assert SignedDelivery.public_key(account) == nil
    end
  end

  describe "Crypto Ed25519 primitives" do
    test "generate / sign / verify round-trips" do
      {public_key, private_key} = Crypto.generate_signing_keypair()
      message = "the quick brown fox"

      signature = Crypto.sign_message(message, private_key)
      assert Crypto.verify_message(message, signature, public_key)
      refute Crypto.verify_message("different", signature, public_key)
    end

    test "verify_message never raises on malformed input" do
      refute Crypto.verify_message("msg", "not-base64!!", "also-bad")
    end
  end
end
