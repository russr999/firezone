defmodule Portal.Policies.EvaluatorPostureTest do
  use ExUnit.Case, async: true

  import Portal.Policies.Evaluator

  alias Portal.{ClientSession, Device}
  alias Portal.Policies.Condition

  defp client, do: %Device{type: :client}

  defp session(posture), do: %ClientSession{posture: posture}

  defp condition(property, operator, values) do
    %Condition{property: property, operator: operator, values: values}
  end

  defp conforms?(conditions, posture) do
    case ensure_conforms(conditions, client(), session(posture), nil) do
      {:ok, _expires_at} -> true
      {:error, _violated} -> false
    end
  end

  describe "client_os_type" do
    test "is_in passes when reported OS is in the set" do
      cond = condition(:client_os_type, :is_in, ["windows", "macos"])
      assert conforms?([cond], %{"os_type" => "windows"})
      refute conforms?([cond], %{"os_type" => "linux"})
    end

    test "is_not_in passes when reported OS is not in the set" do
      cond = condition(:client_os_type, :is_not_in, ["linux"])
      assert conforms?([cond], %{"os_type" => "macos"})
      refute conforms?([cond], %{"os_type" => "linux"})
    end

    test "fails closed when posture is missing" do
      cond = condition(:client_os_type, :is_in, ["windows"])
      refute conforms?([cond], nil)
      refute conforms?([cond], %{})
    end
  end

  describe "version conditions" do
    test "client_os_version passes at or above the minimum" do
      cond = condition(:client_os_version, :is_version_greater_than_or_equal, ["10.0.22000"])
      assert conforms?([cond], %{"os_version" => "10.0.22631"})
      assert conforms?([cond], %{"os_version" => "10.0.22000"})
      refute conforms?([cond], %{"os_version" => "10.0.19045"})
    end

    test "client_app_version reads the client_version posture key" do
      cond = condition(:client_app_version, :is_version_greater_than_or_equal, ["1.5.0"])
      assert conforms?([cond], %{"client_version" => "1.5.7"})
      refute conforms?([cond], %{"client_version" => "1.4.9"})
    end

    test "fails closed when the version signal is missing or unparseable" do
      cond = condition(:client_os_version, :is_version_greater_than_or_equal, ["10.0.0"])
      refute conforms?([cond], %{})
      refute conforms?([cond], %{"os_version" => "unknown"})
    end
  end

  describe "boolean posture conditions" do
    test "disk_encryption required passes only when reported true" do
      cond = condition(:client_disk_encryption, :is, ["true"])
      assert conforms?([cond], %{"disk_encryption" => true})
      refute conforms?([cond], %{"disk_encryption" => false})
      refute conforms?([cond], %{})
    end

    test "firewall can require disabled" do
      cond = condition(:client_firewall, :is, ["false"])
      assert conforms?([cond], %{"firewall_enabled" => false})
      refute conforms?([cond], %{"firewall_enabled" => true})
    end

    test "antivirus required fails closed when unreported (e.g. Linux)" do
      cond = condition(:client_antivirus, :is, ["true"])
      assert conforms?([cond], %{"antivirus_enabled" => true})
      refute conforms?([cond], %{"antivirus_enabled" => nil})
      refute conforms?([cond], %{})
    end
  end

  describe "combined with the violated-properties result" do
    test "reports every violated posture property" do
      conditions = [
        condition(:client_disk_encryption, :is, ["true"]),
        condition(:client_firewall, :is, ["true"])
      ]

      assert {:error, violated} =
               ensure_conforms(conditions, client(), session(%{}), nil)

      assert :client_disk_encryption in violated
      assert :client_firewall in violated
    end
  end
end
