defmodule Portal.SelfHostedUnlockTest do
  @moduledoc """
  Verifies the self-hosted unlock toggle removes all plan limits and unlocks
  all gated features. See SELF_HOSTED_UNLOCK_PLAN.md.

  The test environment defaults `:self_hosted_unlocked` to `false` so the
  commercial-gating suite stays valid; here we flip it on per-process via
  `Portal.Config.put_env_override/2`.
  """
  use Portal.DataCase, async: true

  import Portal.AccountFixtures

  alias Portal.Account
  alias Portal.Billing

  defp unlock!, do: :ok = Portal.Config.put_env_override(:self_hosted_unlocked, true)

  setup do
    %{account: account_fixture()}
  end

  describe "Portal.Config.self_hosted_unlocked?/0" do
    test "defaults to false in the test environment" do
      assert Portal.Config.self_hosted_unlocked?() == false
    end

    test "reflects the per-process override" do
      unlock!()
      assert Portal.Config.self_hosted_unlocked?() == true
    end
  end

  describe "limits are removed when unlocked" do
    test "no limit is ever reported exceeded even past the configured cap",
         %{account: account} do
      account =
        update_account(account, %{
          limits: %{
            users_count: 1,
            monthly_active_users_count: 1,
            service_accounts_count: 1,
            sites_count: 1,
            account_admin_users_count: 1,
            api_clients_count: 1,
            api_tokens_per_client_count: 1
          }
        })

      # Sanity: with the commercial gate active, the cap is enforced.
      assert Billing.users_limit_exceeded?(account, 5) == true
      assert Billing.sites_limit_exceeded?(account, 5) == true

      unlock!()

      refute Billing.users_limit_exceeded?(account, 5)
      refute Billing.seats_limit_exceeded?(account, 5)
      refute Billing.service_accounts_limit_exceeded?(account, 5)
      refute Billing.sites_limit_exceeded?(account, 5)
      refute Billing.admins_limit_exceeded?(account, 5)
      refute Billing.api_clients_limit_exceeded?(account, 5)
      refute Billing.api_tokens_limit_exceeded?(account, 5)
      refute Billing.any_limit_exceeded?(account)
    end

    test "every can_create_* gate allows creation for an active account",
         %{account: account} do
      account = update_account(account, %{limits: %{users_count: 0, sites_count: 0}})

      unlock!()

      assert Billing.can_create_users?(account)
      assert Billing.can_create_service_accounts?(account)
      assert Billing.can_create_sites?(account)
      assert Billing.can_create_admin_users?(account)
      assert Billing.can_create_api_clients?(account)
    end

    test "disabled accounts are still blocked from creation when unlocked",
         %{account: account} do
      account = update_account(account, %{disabled_at: DateTime.utc_now()})

      unlock!()

      refute Account.active?(account)
      refute Billing.can_create_users?(account)
      refute Billing.can_create_sites?(account)
    end

    test "sign-in and connect are not restricted when unlocked",
         %{account: account} do
      account =
        update_account(account, %{
          users_limit_exceeded: true,
          service_accounts_limit_exceeded: true
        })

      # Commercial gate would restrict here.
      assert Billing.client_sign_in_restricted?(account) == true
      assert Billing.client_connect_restricted?(account) == true

      unlock!()

      refute Billing.client_sign_in_restricted?(account)
      refute Billing.client_connect_restricted?(account)
    end
  end

  describe "features are unlocked when unlocked" do
    test "every gated feature reports enabled regardless of the per-account embed",
         %{account: account} do
      # Fixture leaves internet_resource unset and client_to_client false.
      account =
        update_account(account, %{
          features: %{
            policy_conditions: false,
            traffic_filters: false,
            idp_sync: false,
            rest_api: false,
            internet_resource: false,
            client_to_client: false
          }
        })

      # Commercial gate honours the embed: all off.
      refute Account.policy_conditions_enabled?(account)
      refute Account.internet_resource_enabled?(account)

      unlock!()

      assert Account.policy_conditions_enabled?(account)
      assert Account.traffic_filters_enabled?(account)
      assert Account.idp_sync_enabled?(account)
      assert Account.rest_api_enabled?(account)
      assert Account.internet_resource_enabled?(account)
      assert Account.client_to_client_enabled?(account)
    end
  end
end
