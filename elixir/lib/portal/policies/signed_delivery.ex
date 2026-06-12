defmodule Portal.Policies.SignedDelivery do
  @moduledoc """
  Cryptographically signs the policy/resource payload delivered to clients so a
  client can detect tampering or substitution of an unsigned channel push
  (Phase 4 of SELF_HOSTED_UNLOCK_PLAN.md).

  The server signs the JSON serialization of the resources list with the
  account's Ed25519 private key. The client receives the account public key in
  the `init` payload and verifies the signature before applying resources.

  Signing is best-effort: if the account has no keypair (older accounts that
  have not yet had one generated, or a self-hosted deployment that opts out),
  the helpers return `nil` and the payload is delivered unsigned exactly as
  before. Verification on the client is therefore opt-in based on whether a
  public key + signature are present.
  """

  alias Portal.Crypto

  @doc """
  Returns a Base64-encoded Ed25519 signature over the canonical encoding of
  `rendered_resources`, or `nil` when the account has no signing key.

  `rendered_resources` is the already-rendered list (the same value placed in
  the `init` payload's `resources` field), so the signature covers exactly what
  the client receives.
  """
  @spec sign_resources(Portal.Account.t(), list()) :: String.t() | nil
  def sign_resources(%Portal.Account{signing_private_key: nil}, _rendered_resources), do: nil

  def sign_resources(%Portal.Account{signing_private_key: private_key}, rendered_resources) do
    rendered_resources
    |> canonical_encode()
    |> Crypto.sign_message(private_key)
  end

  @doc """
  The account's Base64-encoded Ed25519 public key, or `nil` when none is set.
  Delivered to the client so it can verify signed payloads.
  """
  @spec public_key(Portal.Account.t()) :: String.t() | nil
  def public_key(%Portal.Account{signing_public_key: public_key}), do: public_key

  @doc """
  Verifies a signature produced by `sign_resources/2`. Provided for tests and
  any server-side re-verification. The client performs the authoritative check.
  """
  @spec verify_resources(Portal.Account.t(), list(), String.t()) :: boolean()
  def verify_resources(%Portal.Account{signing_public_key: nil}, _rendered, _sig), do: false

  def verify_resources(%Portal.Account{signing_public_key: public_key}, rendered_resources, sig) do
    rendered_resources
    |> canonical_encode()
    |> Crypto.verify_message(sig, public_key)
  end

  # Canonical, deterministic encoding the signature is computed over. Jason
  # preserves insertion/struct order; the client must reconstruct the identical
  # byte sequence to verify. Resources are rendered server-side in a stable
  # order, so encoding the list as-is is deterministic for a given payload.
  defp canonical_encode(rendered_resources) do
    Jason.encode!(rendered_resources)
  end
end
