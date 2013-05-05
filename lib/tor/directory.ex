defmodule Tor.Directory do
  def authorities do
    [ Tor.Authority[ name: "moria1",
                     identity: "D586D18309DED4CD6D57C18FDB97EFA96D330566",
                     version: 3,
                     address: "128.31.0.39",
                     port: 9131 ],

      Tor.Authority[ name: "tor26",
                     identity: "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4",
                     version: 1,
                     address: "86.59.21.38",
                     port: 80 ],

      Tor.Authority[ name: "dizum",
                     identity: "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58",
                     version: 3,
                     address: "86.59.21.38",
                     port: 80 ] ]
  end

  defrecordp :directory, date: nil, expires: nil, socket: nil

  def fetch(from // authorities) do
    case connect(from) do
      { :ok, sock } ->
        sock.send!("GET /tor/server/all HTTP/1.0\r\n\r\n")

        sock.recv!
        "Date: " <> date = sock.recv!
        sock.recv!
        sock.recv!
        sock.recv!
        "Expires: " <> expires = sock.recv!
        sock.recv!

        { :ok, directory(socket: sock,
          date: :dh_date.parse(String.rstrip(date)),
          expires: :dh_date.parse(String.rstrip(date))) }

      error -> error
    end
  end

  def fetch!(from // authorities) do
    case fetch(from) do
      { :ok, directory } ->
        directory

      { :error, error } ->
        raise RuntimeError, message: error
    end
  end

  defp connect([]) do
    { :error, "failed to connect to all authorities" }
  end

  defp connect([to | rest]) do
    case connect(to) do
      { :ok, sock } ->
        { :ok, sock }

      { :error, _ } ->
        connect(rest)
    end
  end

  defp connect(to) do
    Socket.TCP.connect(to.address, to.port, packet: :line)
  end

  defp router(text, sock) do
    case sock.recv! do
      "router " <> _ = line ->
        { Tor.Router.parse(text), line }

     line ->
        router(text <> line, sock)
    end
  end

  def fold(first, acc, fun, directory(socket: sock) = self) do
    fold(sock.recv!, acc, fun, self)
  end

  def fold(first, acc, fun, directory(socket: sock) = self) do
    case router(first, sock) do
      { router, first } ->
        fun.(router, acc)
        fold(first, acc, fun, self)

      nil ->
        acc
    end
  end

  def each(fun, self) do
    fold nil, fn router, _ ->
      fun.(router)
    end
  end

  def to_list(self) do
    fold [], fn router, acc ->
      [router | acc]
    end
  end
end

"""

    "moria1 orport=9101 no-v2 "
      "v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 "
      "128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31",

    "tor26 v1 orport=443 v3ident=14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 "
      "86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D",

    "dizum orport=443 v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 "
      "194.109.206.212:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",

    "Tonga orport=443 bridge no-v2 82.94.251.203:80 "
      "4A0C CD2D DC79 9508 3D73 F5D6 6710 0C8A 5831 F16D",

    "turtles orport=9090 no-v2 "
      "v3ident=27B6B5996C426270A5C95488AA5BCEB6BCC86956 "
      "76.73.17.194:9030 F397 038A DC51 3361 35E7 B80B D99C A384 4360 292B",

    "gabelmoo orport=443 no-v2 "
      "v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 "
      "212.112.245.170:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",

    "dannenberg orport=443 no-v2 "
      "v3ident=585769C78764D58426B8B52B6651A5A71137189A "
      "193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",

    "urras orport=80 no-v2 v3ident=80550987E1D626E3EBA5E5E75A458DE0626D088C "
      "208.83.223.34:443 0AD3 FA88 4D18 F89E EA2D 89C0 1937 9E0E 7FD9 4417",

    "maatuska orport=80 no-v2 "
      "v3ident=49015F787433103580E3B66A1707A00E60F2D15B "
      "171.25.193.9:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",

    "Faravahar orport=443 no-v2 "
      "v3ident=EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97 "
      "154.35.32.5:80 CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC",

"""
