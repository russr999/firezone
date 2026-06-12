defmodule Portal.SAML.AuthProvider do
  @moduledoc """
  SAML 2.0 authentication provider (Phase 6).

  Mirrors the registration contract of `Portal.OIDC.AuthProvider` — a schema
  linked to the parent `Portal.AuthProvider` row plus the two
  `default_*_session_lifetime_secs/0` functions the auth controllers call. SAML
  differs from OIDC in its configuration: instead of a discovery document and
  client credentials it stores the IdP single-sign-on URL, the IdP signing
  certificate (used to validate assertions), and the service-provider entity ID.

  The assertion-consumer flow (request → IdP → ACS callback) is handled by the
  web SAML controller; this schema holds the IdP configuration it needs.
  """
  use Ecto.Schema
  import Ecto.Changeset
  import Portal.Changeset

  @primary_key false
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @default_portal_session_lifetime_secs 28_800
  @default_client_session_lifetime_secs 604_800

  schema "saml_auth_providers" do
    field :id, :binary_id, primary_key: true

    belongs_to :account, Portal.Account

    belongs_to :auth_provider, Portal.AuthProvider,
      foreign_key: :id,
      define_field: false

    field :name, :string, default: "SAML"

    field :context, Ecto.Enum,
      values: ~w[clients_and_portal clients_only portal_only]a,
      default: :clients_and_portal

    # IdP single-sign-on (redirect/POST) URL the SP sends AuthnRequests to.
    field :idp_sso_url, :string

    # IdP entity ID (issuer) expected in assertions.
    field :idp_entity_id, :string

    # PEM-encoded X.509 certificate used to verify the IdP's assertion signature.
    field :idp_certificate, :string

    # Service-provider entity ID this Firezone account presents to the IdP.
    field :sp_entity_id, :string

    # Assertion attribute that carries the user's email.
    field :email_attribute, :string, default: "email"

    field :client_session_lifetime_secs, :integer
    field :portal_session_lifetime_secs, :integer

    field :is_verified, :boolean, virtual: true, default: false
    field :is_disabled, :boolean, read_after_writes: true, default: false
    field :is_default, :boolean, read_after_writes: true, default: false

    timestamps()
  end

  def changeset(%Ecto.Changeset{} = changeset) do
    changeset
    |> validate_required([
      :name,
      :context,
      :idp_sso_url,
      :idp_entity_id,
      :idp_certificate,
      :email_attribute
    ])
    |> validate_uri(:idp_sso_url, block_private_ips: true)
    |> validate_length(:idp_sso_url, min: 1, max: 2000)
    |> validate_length(:idp_entity_id, min: 1, max: 2000)
    |> validate_length(:idp_certificate, min: 1, max: 10_000)
    |> validate_length(:email_attribute, min: 1, max: 255)
    |> assoc_constraint(:account)
    |> assoc_constraint(:auth_provider)
    |> unique_constraint(:name,
      name: :saml_auth_providers_account_id_name_index,
      message: "A SAML authentication provider with this name already exists."
    )
  end

  def default_portal_session_lifetime_secs, do: @default_portal_session_lifetime_secs
  def default_client_session_lifetime_secs, do: @default_client_session_lifetime_secs
end
