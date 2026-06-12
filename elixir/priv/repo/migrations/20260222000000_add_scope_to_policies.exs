defmodule Portal.Repo.Migrations.AddScopeToPolicies do
  use Ecto.Migration

  def change do
    alter table(:policies) do
      add(:scope, :string, null: false, default: "all")
    end
  end
end
