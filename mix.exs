defmodule Tor.Mixfile do
  use Mix.Project

  def project do
    [ app: :tor,
      version: "0.0.1",
      deps: deps ]
  end

  # Configuration for the OTP application
  def application do
    [ applications: [:socket] ]
  end

  # Returns the list of dependencies in the format:
  # { :foobar, "0.1", git: "https://github.com/elixir-lang/foobar.git" }
  defp deps do
    [ { :socket, %r(.*), github: "meh/elixir-socket" },
      { :dh_date, %r(.*), github: "zotonic/dh_date" } ]
  end
end
