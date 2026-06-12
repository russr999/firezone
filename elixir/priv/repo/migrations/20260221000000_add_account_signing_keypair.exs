defmodule Portal.Repo.Migrations.AddAccountSigningKeypair do
  use Ecto.Migration

  def change do
    alter table(:accounts) do
      add(:signing_public_key, :string)
      add(:signing_private_key, :string)
    end
  end
end
