defrecord Tor.Router, [:name, :ip, :port, :attributes] do
  defrecord Port, [:tor, :socks, :directory]
  defrecord Bandwidth, [:average, :burst, :observed]

  defmodule Policy do
    defrecordp :policy, list: []

    def new do
      policy()
    end

    def accept(pattern, policy(list: list)) do
      policy(list: list)
    end

    def reject(pattern, policy(list: list)) do
      policy(list: list)
    end
  end

  def parse(text) do
    [header | rest] = String.split(text, "\n")
    ["router", name, ip, tor_port, socks_port, directory_port] = String.split(header)

    Tor.Router[ name: name,
                ip: ip,
                port: Port[ tor: parse_port(tor_port),
                            socks: parse_port(socks_port),
                            directory: parse_port(directory_port) ],
                attributes: parse(Keyword.new, rest) ]
  end

  defp parse_port("0"), do: nil
  defp parse_port(port), do: binary_to_integer(port)

  defp parse_bool("0"), do: false
  defp parse_bool("1"), do: true

  defp parse(attrs, []) do
    attrs
  end

  defp parse(attrs, ["bandwidth " <> _ = line | rest]) do
    ["bandwidth", average, burst, observed] = String.split(line)

    parse(Keyword.put(attrs, :bandwidth, Bandwidth[
      average:  binary_to_integer(average),
      burst:    binary_to_integer(burst),
      observed: binary_to_integer(observed)
    ]), rest)
  end

  defp parse(attrs, ["platform " <> platform | rest]) do
    parse(Keyword.put(attrs, :platform, platform), rest)
  end

  defp parse(attrs, ["published " <> published | rest]) do
    parse(Keyword.put(attrs, :published, :dh_date.parse(published)), rest)
  end

  defp parse(attrs, ["fingerprint " <> fingerprint | rest]) do
    parse(Keyword.put(attrs, :fingerprint, fingerprint), rest)
  end

  defp parse(attrs, ["hibernating " <> hibernating | rest]) do
    parse(Keyword.put(attrs, :hibernating, parse_bool(hibernating)), rest)
  end

  defp parse(attrs, ["uptime " <> uptime | rest]) do
    parse(Keyword.put(attrs, :uptime, binary_to_integer(uptime)), rest)
  end

  defp parse(attrs, ["onion-key " <> key | rest]) do
    parse(Keyword.put(attrs, :keys, Keyword.put(Keyword.get(attrs, :keys, []), :onion, key)), rest)
  end

  defp parse(attrs, ["ntor-onion-key " <> key | rest]) do
    parse(Keyword.put(attrs, :keys, Keyword.put(Keyword.get(attrs, :keys, []), :ntor, key)), rest)
  end

  defp parse(attrs, ["signing-key " <> key | rest]) do
    parse(Keyword.put(attrs, :keys, Keyword.put(Keyword.get(attrs, :keys, []), :signing, key)), rest)
  end

  defp parse(attrs, ["accept " <> pattern | rest]) do
    parse(Keyword.put(attrs, :policy, Keyword.get(attrs, :policy, Policy.new).accept(pattern)), rest)
  end

  defp parse(attrs, ["reject " <> pattern | rest]) do
    parse(Keyword.put(attrs, :policy, Keyword.get(attrs, :policy, Policy.new).reject(pattern)), rest)
  end

  defp parse(attrs, ["router-signature " <> begin | rest]) do
    parse(Keyword.put(attrs, :signature, begin <> "\n" <> String.join(rest, "\n")), rest)
  end

  defp parse(attrs, [_ | rest]) do
    parse(attrs, rest)
  end

  def exit?(self) do
    false
  end
end
