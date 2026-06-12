defmodule Portal.Repo.Migrations.AddKindToResources do
  use Ecto.Migration

  def change do
    alter table(:resources) do
      add(:kind, :string, null: false, default: "allow")
    end
  end
end
