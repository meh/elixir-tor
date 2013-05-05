defrecord Tor.Authority, [:name, :version, :identity, :address, :port, :tor] do
  def directory(self) do
    Tor.Directory.fetch(self)
  end

  def directory!(self) do
    Tor.Directory.fetch!(self)
  end
end
