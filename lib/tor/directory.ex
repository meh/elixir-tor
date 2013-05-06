defmodule Tor.Directory do
  defrecordp :directory, date: nil, expires: nil, socket: nil

  def fetch(from // Tor.authorities) do
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

  def fetch!(from // Tor.authorities) do
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
    case sock.recv do
      { :ok, "router " <> _ = line } ->
        { Tor.Router.parse(text), line }

      { :error, _ } ->
        { Tor.Router.parse(text), nil }

      { :ok, line } ->
        router(text <> line, sock)
    end
  end

  def fold(acc, fun, directory(socket: sock) = self) do
    fold(sock.recv!, acc, fun, self)
  end

  def fold(first, acc, fun, directory(socket: sock) = self) do
    case router(first, sock) do
      { router, nil } ->
        fun.(router, acc)

      { router, first } ->
        fold(first, fun.(router, acc), fun, self)

      nil ->
        acc
    end
  end

  def each(fun, self) do
    self.fold nil, fn router, _ ->
      fun.(router)
    end
  end

  def to_list(self) do
    self.fold [], fn router, acc ->
      [router | acc]
    end
  end
end
