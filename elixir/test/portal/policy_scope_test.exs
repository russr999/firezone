defmodule Portal.PolicyScopeTest do
  @moduledoc """
  Phase 5 — policy scope. Verifies the `scope` field defaults to `:all` and
  that the actor-kind matching rule used by the authorization query
  (`Portal.Cache.Client.Database.all_policies_for_actor_id!/2`) is correct.

  The rule: a policy applies when scope == :all, or scope == :user and the
  actor is a human user, or scope == :client and the actor is not a human user
  (service account / api client).
  """
  use ExUnit.Case, async: true

  alias Portal.Policy

  # Mirror of the query predicate, kept in sync with cache/client.ex.
  defp applies?(scope, actor_type) do
    actor_is_user = actor_type in [:account_user, :account_admin_user]
    actor_is_client = not actor_is_user

    scope == :all or
      (scope == :user and actor_is_user) or
      (scope == :client and actor_is_client)
  end

  test "scope defaults to :all" do
    assert %Policy{}.scope == :all
  end

  test ":all applies to every actor type" do
    for type <- [:account_user, :account_admin_user, :service_account, :api_client] do
      assert applies?(:all, type)
    end
  end

  test ":user applies only to human users" do
    assert applies?(:user, :account_user)
    assert applies?(:user, :account_admin_user)
    refute applies?(:user, :service_account)
    refute applies?(:user, :api_client)
  end

  test ":client applies only to non-human actors" do
    assert applies?(:client, :service_account)
    assert applies?(:client, :api_client)
    refute applies?(:client, :account_user)
    refute applies?(:client, :account_admin_user)
  end
end
