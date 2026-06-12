defmodule Portal.Repo.Migrations.CreateJumpcloudDirectories do
  use Ecto.Migration

  def change do
    create table(:jumpcloud_directories, primary_key: false) do
      add(:id, :binary_id, primary_key: true, null: false)
      add(:account_id, :binary_id, null: false)

      add(:api_key, :string, null: false)

      add(:name, :string, null: false, default: "JumpCloud")
      add(:errored_at, :utc_datetime_usec)
      add(:is_disabled, :boolean, null: false, default: false)
      add(:disabled_reason, :string)
      add(:synced_at, :utc_datetime_usec)
      add(:error_message, :string)
      add(:error_email_count, :integer, null: false, default: 0)
      add(:is_verified, :boolean, null: false, default: false)

      timestamps(type: :utc_datetime_usec)
    end

    execute(
      "ALTER TABLE jumpcloud_directories ADD CONSTRAINT jumpcloud_directories_account_id_fkey FOREIGN KEY (account_id) REFERENCES accounts(id)",
      "ALTER TABLE jumpcloud_directories DROP CONSTRAINT jumpcloud_directories_account_id_fkey"
    )

    execute(
      "ALTER TABLE jumpcloud_directories ADD CONSTRAINT jumpcloud_directories_id_fkey FOREIGN KEY (account_id, id) REFERENCES directories(account_id, id) ON DELETE CASCADE",
      "ALTER TABLE jumpcloud_directories DROP CONSTRAINT jumpcloud_directories_id_fkey"
    )

    create(
      unique_index(:jumpcloud_directories, [:account_id, :name],
        name: :jumpcloud_directories_account_id_name_index
      )
    )

    # Allow `jumpcloud` in the directories type check constraint.
    execute(
      """
      ALTER TABLE directories DROP CONSTRAINT IF EXISTS type_must_be_valid;
      ALTER TABLE directories ADD CONSTRAINT type_must_be_valid
        CHECK (type IN ('google', 'entra', 'okta', 'jumpcloud'));
      """,
      """
      ALTER TABLE directories DROP CONSTRAINT IF EXISTS type_must_be_valid;
      ALTER TABLE directories ADD CONSTRAINT type_must_be_valid
        CHECK (type IN ('google', 'entra', 'okta'));
      """
    )
  end
end
