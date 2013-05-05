defmodule Tor do
  defrecord Authority, [:name, :address, :port]

  def authorities do
    [ Authority[name: "tor26", address: "86.59.21.38", port: 80] ]
  end

  def routers do
    case :gen_tcp.connect(authorities.address, 80, [{ :active, false }, { :packet, :line }, :binary]) do
      { :ok, sock } ->
        :gen_tcp.send(sock, "GET /tor/server/all HTTP/1.0\r\n\r\n")

      error -> error
    end
  end

end
