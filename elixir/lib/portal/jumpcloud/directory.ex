defmodule Portal.JumpCloud.Directory do
  @moduledoc """
  JumpCloud directory (Phase 6). Mirrors the `Portal.Okta.Directory` registration
  contract, but JumpCloud authenticates with a simple API key rather than Okta's
  DPoP-signed client assertion, so the schema stores an `api_key` instead of a
  JWK + key id.

  The directory-sync worker (users + groups + memberships) reuses the shared,
  provider-agnostic batch-upsert pipeline; see SELF_HOSTED_UNLOCK_PLAN.md
  Phase 6 for the sync-implementation follow-up.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @type t :: %__MODULE__{
          id: Ecto.UUID.t(),
          account_id: Ecto.UUID.t(),
          api_key: String.t(),
          name: String.t(),
          errored_at: DateTime.t() | nil,
          is_disabled: boolean(),
          disabled_reason: String.t() | nil,
          synced_at: DateTime.t() | nil,
          error_message: String.t() | nil,
          error_email_count: non_neg_integer(),
          is_verified: boolean(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  schema "jumpcloud_directories" do
    belongs_to :account, Portal.Account

    belongs_to :directory, Portal.Directory,
      foreign_key: :id,
      define_field: false

    field :api_key, :string, redact: true

    field :name, :string, default: "JumpCloud"
    field :errored_at, :utc_datetime_usec
    field :is_disabled, :boolean, default: false, read_after_writes: true
    field :disabled_reason, :string
    field :synced_at, :utc_datetime_usec
    field :error_message, :string
    field :error_email_count, :integer, default: 0, read_after_writes: true
    field :is_verified, :boolean, default: false, read_after_writes: true

    timestamps()
  end

  def changeset(%Ecto.Changeset{} = changeset) do
    changeset
    |> validate_required([:name, :api_key, :is_verified])
    |> validate_length(:api_key, min: 1, max: 255)
    |> validate_length(:name, min: 1, max: 255)
    |> validate_number(:error_email_count, greater_than_or_equal_to: 0)
    |> assoc_constraint(:account)
    |> assoc_constraint(:directory)
    |> unique_constraint(:name,
      name: :jumpcloud_directories_account_id_name_index,
      message: "A JumpCloud directory with this name already exists."
    )
  end
end
