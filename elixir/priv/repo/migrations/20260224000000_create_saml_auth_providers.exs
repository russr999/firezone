defmodule Portal.Repo.Migrations.CreateSamlAuthProviders do
  use Ecto.Migration

  def change do
    create table(:saml_auth_providers, primary_key: false) do
      add(:id, :binary_id, primary_key: true, null: false)
      add(:account_id, :binary_id, null: false)

      add(:name, :string, null: false, default: "SAML")
      add(:context, :string, null: false, default: "clients_and_portal")

      add(:idp_sso_url, :string, null: false)
      add(:idp_entity_id, :string, null: false)
      add(:idp_certificate, :text, null: false)
      add(:sp_entity_id, :string)
      add(:email_attribute, :string, null: false, default: "email")

      add(:client_session_lifetime_secs, :integer)
      add(:portal_session_lifetime_secs, :integer)

      add(:is_disabled, :boolean, null: false, default: false)
      add(:is_default, :boolean, null: false, default: false)

      timestamps(type: :utc_datetime_usec)
    end

    execute(
      "ALTER TABLE saml_auth_providers ADD CONSTRAINT saml_auth_providers_account_id_fkey FOREIGN KEY (account_id) REFERENCES accounts(id)",
      "ALTER TABLE saml_auth_providers DROP CONSTRAINT saml_auth_providers_account_id_fkey"
    )

    execute(
      "ALTER TABLE saml_auth_providers ADD CONSTRAINT saml_auth_providers_id_fkey FOREIGN KEY (account_id, id) REFERENCES auth_providers(account_id, id) ON DELETE CASCADE",
      "ALTER TABLE saml_auth_providers DROP CONSTRAINT saml_auth_providers_id_fkey"
    )

    create(
      unique_index(:saml_auth_providers, [:account_id, :name],
        name: :saml_auth_providers_account_id_name_index
      )
    )

    # Allow `saml` in the auth_providers type check constraint.
    execute(
      """
      ALTER TABLE auth_providers DROP CONSTRAINT IF EXISTS type_must_be_valid;
      ALTER TABLE auth_providers ADD CONSTRAINT type_must_be_valid
        CHECK (type IN ('google', 'okta', 'entra', 'oidc', 'saml', 'email_otp', 'userpass'));
      """,
      """
      ALTER TABLE auth_providers DROP CONSTRAINT IF EXISTS type_must_be_valid;
      ALTER TABLE auth_providers ADD CONSTRAINT type_must_be_valid
        CHECK (type IN ('google', 'okta', 'entra', 'oidc', 'email_otp', 'userpass'));
      """
    )
  end
end
