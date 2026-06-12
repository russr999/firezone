defmodule Portal.Repo.Migrations.AddClientSessionsPosture do
  use Ecto.Migration

  def change do
    alter table(:client_sessions) do
      add(:posture, :map)
    end
  end
end
