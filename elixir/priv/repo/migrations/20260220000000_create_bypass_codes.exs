defmodule Portal.Repo.Migrations.CreateBypassCodes do
  use Ecto.Migration

  def change do
    create table(:bypass_codes, primary_key: false) do
      add(:account_id, :binary_id, primary_key: true, null: false)
      add(:id, :binary_id, primary_key: true, null: false, default: fragment("gen_random_uuid()"))

      add(:device_id, :binary_id, null: false)
      add(:issued_by_actor_id, :binary_id)

      add(:secret_salt, :string, null: false)
      add(:secret_hash, :string, null: false)

      add(:reason, :string)

      add(:expires_at, :utc_datetime_usec, null: false)

      add(:max_uses, :integer, null: false, default: 1)
      add(:redeemed_count, :integer, null: false, default: 0)
      add(:last_redeemed_at, :utc_datetime_usec)

      add(:revoked_at, :utc_datetime_usec)

      timestamps(type: :utc_datetime_usec)
    end

    execute(
      "ALTER TABLE bypass_codes ADD CONSTRAINT bypass_codes_account_id_fkey FOREIGN KEY (account_id) REFERENCES accounts(id)",
      "ALTER TABLE bypass_codes DROP CONSTRAINT bypass_codes_account_id_fkey"
    )

    execute(
      "ALTER TABLE bypass_codes ADD CONSTRAINT bypass_codes_device_id_fkey FOREIGN KEY (account_id, device_id) REFERENCES clients(account_id, id) ON DELETE CASCADE",
      "ALTER TABLE bypass_codes DROP CONSTRAINT bypass_codes_device_id_fkey"
    )

    create(index(:bypass_codes, [:account_id, :device_id]))
  end
end
