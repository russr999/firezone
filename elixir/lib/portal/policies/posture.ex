defmodule Portal.Policies.Posture do
  @moduledoc """
  Device posture report helpers.

  A posture report is a client-supplied, normalized map describing the security
  state of the connecting device (OS type/version, disk encryption, host
  firewall, antivirus presence, client version). It is normalized at connect
  time, stored on the `Portal.ClientSession`, and evaluated against policy
  conditions in `Portal.Policies.Evaluator`.

  Posture is reported by the client; it is advisory signal, not attestation.
  Conditions therefore fail closed: when a required posture signal is missing
  (an older client that does not report posture, or a field the client could
  not determine), the condition is treated as violated.
  """

  @os_types ~w[windows macos linux ios android chromeos]

  @doc "Canonical OS type strings a client may report."
  def os_types, do: @os_types

  @doc """
  Normalizes a raw, client-supplied posture map into a known-shape map with
  string keys and validated value types. Returns `nil` for any non-map input so
  that a missing or malformed report is indistinguishable from "no posture
  reported" (which fails posture conditions closed).

  Only the recognized keys are retained — arbitrary client-supplied keys are
  dropped, so the persisted blob can never carry unexpected data.

  Accepts either an already-decoded map or a JSON object string (the client
  transmits posture as a single JSON-encoded `posture` query parameter on the
  WebSocket connect). Any other input, or a JSON string that does not decode to
  an object, yields `nil`.
  """
  @spec normalize(term()) :: %{String.t() => term()} | nil
  def normalize(json) when is_binary(json) do
    case Jason.decode(json) do
      {:ok, map} when is_map(map) -> normalize(map)
      _ -> nil
    end
  end

  def normalize(map) when is_map(map) do
    %{
      "os_type" => normalize_os_type(get(map, "os_type")),
      "os_version" => normalize_string(get(map, "os_version")),
      "client_version" => normalize_string(get(map, "client_version")),
      "disk_encryption" => normalize_bool(get(map, "disk_encryption")),
      "firewall_enabled" => normalize_bool(get(map, "firewall_enabled")),
      "antivirus_enabled" => normalize_bool(get(map, "antivirus_enabled"))
    }
  end

  def normalize(_other), do: nil

  # Accept either string or atom keys from the caller (JSON gives strings).
  defp get(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, String.to_atom(key))
    end
  end

  defp normalize_os_type(value) when is_binary(value) do
    downcased = String.downcase(value)
    if downcased in @os_types, do: downcased, else: nil
  end

  defp normalize_os_type(_), do: nil

  defp normalize_string(value) when is_binary(value) do
    case String.trim(value) do
      "" -> nil
      trimmed -> String.slice(trimmed, 0, 255)
    end
  end

  defp normalize_string(_), do: nil

  defp normalize_bool(true), do: true
  defp normalize_bool(false), do: false
  defp normalize_bool("true"), do: true
  defp normalize_bool("false"), do: false
  defp normalize_bool(_), do: nil

  @doc """
  Compares two dotted version strings (e.g. `"10.0.22631"`, `"1.5.7"`) by their
  leading numeric segments. Segments are split on `.` and `-`; missing trailing
  segments are treated as `0`. Returns `:lt | :eq | :gt`, or `:error` when
  either input has no parseable leading numeric segment.

  This is intentionally a numeric dotted comparison, not strict SemVer, because
  OS versions (Windows build numbers, macOS `sw_vers`) are not SemVer.
  """
  @spec compare_versions(term(), term()) :: :lt | :eq | :gt | :error
  def compare_versions(a, b) do
    with {:ok, a_segments} <- parse_version(a),
         {:ok, b_segments} <- parse_version(b) do
      compare_segments(a_segments, b_segments)
    else
      _ -> :error
    end
  end

  @doc """
  Returns true when `reported` is greater than or equal to `minimum`. Returns
  false (fail closed) when either version is missing or unparseable.
  """
  @spec version_at_least?(term(), term()) :: boolean()
  def version_at_least?(reported, minimum) do
    case compare_versions(reported, minimum) do
      :gt -> true
      :eq -> true
      _ -> false
    end
  end

  defp parse_version(value) when is_binary(value) do
    segments =
      value
      |> String.split([".", "-"], trim: true)
      |> Enum.map(&leading_integer/1)
      |> Enum.take_while(&(&1 != :error))

    case segments do
      [] -> :error
      segments -> {:ok, segments}
    end
  end

  defp parse_version(_), do: :error

  # Parse the leading run of digits from a segment ("22631" -> 22631,
  # "1rc" -> 1, "rc" -> :error).
  defp leading_integer(segment) do
    case Integer.parse(segment) do
      {int, _rest} -> int
      :error -> :error
    end
  end

  defp compare_segments([], []), do: :eq
  defp compare_segments([], rest), do: compare_segments([0], rest)
  defp compare_segments(rest, []), do: compare_segments(rest, [0])

  defp compare_segments([a | a_rest], [b | b_rest]) do
    cond do
      a < b -> :lt
      a > b -> :gt
      true -> compare_segments(a_rest, b_rest)
    end
  end
end
