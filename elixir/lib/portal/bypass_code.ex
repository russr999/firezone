defmodule Portal.BypassCode do
  @moduledoc """
  A time-boxed, admin-issued code that temporarily lifts always-on / tunnel-lock
  enforcement on a client (see the `alwaysOn` / `lockTunnel` MDM policies and
  SELF_HOSTED_UNLOCK_PLAN.md Phase 3).

  Only a salted hash of the code is stored — never the plaintext. A code is
  valid until `expires_at`, may be redeemed at most `max_uses` times, and every
  redemption is recorded (`redeemed_count`, `last_redeemed_at`) so administrators
  retain an audit trail.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "bypass_codes" do
    belongs_to :account, Portal.Account, primary_key: true

    # The client this code is scoped to. A code is only valid for its device.
    belongs_to :device, Portal.Device, foreign_key: :device_id, references: :id

    # The admin actor who issued the code, for the audit trail.
    belongs_to :issued_by_actor, Portal.Actor

    # Plaintext is shown once at creation and never stored.
    field :secret, :string, virtual: true, redact: true
    field :secret_salt, :string, redact: true
    field :secret_hash, :string, redact: true

    field :reason, :string

    field :expires_at, :utc_datetime_usec

    field :max_uses, :integer, default: 1
    field :redeemed_count, :integer, default: 0
    field :last_redeemed_at, :utc_datetime_usec

    field :revoked_at, :utc_datetime_usec

    timestamps()
  end

  @doc """
  Builds a changeset for a newly-issued bypass code. The caller supplies the
  generated salt + hash (via `Portal.BypassCodes`) — this schema never sees the
  plaintext beyond the virtual `:secret` field used for one-time display.
  """
  def changeset(%__MODULE__{} = bypass_code, attrs) do
    bypass_code
    |> cast(attrs, [
      :account_id,
      :device_id,
      :issued_by_actor_id,
      :secret_salt,
      :secret_hash,
      :reason,
      :expires_at,
      :max_uses
    ])
    |> validate_required([:account_id, :device_id, :secret_salt, :secret_hash, :expires_at])
    |> validate_number(:max_uses, greater_than: 0)
    |> validate_length(:reason, max: 255)
    |> assoc_constraint(:account)
    |> assoc_constraint(:device)
  end

  @doc "True when the code can still be redeemed at `now`."
  @spec redeemable?(t(), DateTime.t()) :: boolean()
  def redeemable?(%__MODULE__{} = code, now) do
    is_nil(code.revoked_at) and
      DateTime.compare(now, code.expires_at) == :lt and
      code.redeemed_count < code.max_uses
  end
end
