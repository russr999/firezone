defmodule Portal.BypassCodeTest do
  use ExUnit.Case, async: true

  alias Portal.BypassCode

  defp code(attrs) do
    struct(
      %BypassCode{
        revoked_at: nil,
        max_uses: 1,
        redeemed_count: 0,
        expires_at: ~U[2030-01-01 00:00:00Z]
      },
      attrs
    )
  end

  describe "redeemable?/2" do
    @now ~U[2026-06-12 00:00:00Z]

    test "true for an unredeemed, unexpired, unrevoked code" do
      assert BypassCode.redeemable?(code(%{}), @now)
    end

    test "false once expired" do
      refute BypassCode.redeemable?(code(%{expires_at: ~U[2026-01-01 00:00:00Z]}), @now)
    end

    test "false once revoked" do
      refute BypassCode.redeemable?(code(%{revoked_at: ~U[2026-05-01 00:00:00Z]}), @now)
    end

    test "false once uses are exhausted" do
      refute BypassCode.redeemable?(code(%{max_uses: 2, redeemed_count: 2}), @now)
      assert BypassCode.redeemable?(code(%{max_uses: 2, redeemed_count: 1}), @now)
    end
  end
end
