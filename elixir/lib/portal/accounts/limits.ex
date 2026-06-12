defmodule Portal.Accounts.Limits do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  embedded_schema do
    field :users_count, :integer
    field :monthly_active_users_count, :integer
    field :service_accounts_count, :integer
    field :sites_count, :integer
    field :account_admin_users_count, :integer
    field :api_clients_count, :integer
    field :api_tokens_per_client_count, :integer
    field :api_refill_rate, :integer
    field :api_capacity, :integer
    field :ingestion_refill_rate, :integer
    field :ingestion_capacity, :integer
  end

  @doc """
  Returns true if the limit is unlimited (nil or less than or equal to zero)
  """
  def unlimited?(nil), do: true
  def unlimited?(limit) when is_integer(limit) and limit <= 0, do: true
  def unlimited?(_limit), do: false

  def changeset(limits \\ %__MODULE__{}, attrs) do
    fields = ~w[
      users_count
      monthly_active_users_count
      service_accounts_count
      sites_count
      account_admin_users_count
      api_clients_count
      api_tokens_per_client_count
      api_refill_rate
      api_capacity
      ingestion_refill_rate
      ingestion_capacity
    ]a

    limits
    |> cast(attrs, fields)
    |> validate_number(:users_count, greater_than_or_equal_to: 0, allow_nil: true)
    |> validate_number(:monthly_active_users_count, greater_than_or_equal_to: 0, allow_nil: true)
    |> validate_number(:service_accounts_count, greater_than_or_equal_to: 0, allow_nil: true)
    |> validate_number(:sites_count, greater_than_or_equal_to: 0, allow_nil: true)
    |> validate_number(:account_admin_users_count, greater_than_or_equal_to: 0, allow_nil: true)
    |> validate_number(:api_clients_count, greater_than_or_equal_to: 0, allow_nil: true)
    |> validate_number(:api_tokens_per_client_count, greater_than_or_equal_to: 0, allow_nil: true)
    |> validate_number(:api_refill_rate, greater_than_or_equal_to: 0, allow_nil: true)
    |> validate_number(:api_capacity, greater_than_or_equal_to: 0, allow_nil: true)
    |> validate_number(:ingestion_refill_rate, greater_than_or_equal_to: 0, allow_nil: true)
    |> validate_number(:ingestion_capacity, greater_than_or_equal_to: 0, allow_nil: true)
  end
end
