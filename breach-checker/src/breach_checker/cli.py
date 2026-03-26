import asyncio
import getpass
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from breach_checker.checker import check_password, check_email

app = typer.Typer(
    name="breach-checker",
    no_args_is_help=True,
    help="Verificador seguro de credenciais comprometidas.",
)
console = Console()


@app.command()
def check_pwd(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    """Verifica se uma password foi comprometida (k-Anonymity)."""
    console.print("[bold]Introduz a password[/bold] (sem echo):")
    password = getpass.getpass(prompt="")

    if not password:
        console.print("[red]Erro: password vazia[/red]")
        raise typer.Exit(1)

    with console.status("[bold]A verificar via k-Anonymity...[/bold]"):
        result = asyncio.run(check_password(password))

    del password

    if result.is_compromised:
        console.print(
            Panel(
                f"[bold red]COMPROMETIDA[/bold red]\n"
                f"Encontrada {result.occurrence_count:,} vezes em vazamentos.",
                border_style="red",
            )
        )
        raise typer.Exit(2)

    console.print(
        Panel("[bold green]NÃO ENCONTRADA[/bold green]", border_style="green")
    )


@app.command()
def check_email(
    email: str = typer.Argument(help="Email a verificar"),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", envvar="HIBP_API_KEY"
    ),
) -> None:
    """Verifica se um email aparece em bases de dados de vazamentos."""
    if not api_key:
        console.print(
            "[red]Erro: define HIBP_API_KEY no .env ou usa --api-key[/red]"
        )
        raise typer.Exit(1)

    with console.status(f"[bold]A verificar {email}...[/bold]"):
        result = asyncio.run(check_email(email, api_key))

    if not result.is_compromised:
        console.print(Panel("[green]Email limpo.[/green]", border_style="green"))
        return

    table = Table(title=f"{result.breach_count} vazamento(s)")
    table.add_column("Serviço", style="bold")
    table.add_column("Data")
    table.add_column("Dados")
    table.add_column("Verificado")

    for b in result.breaches:
        table.add_row(
            b.name,
            b.breach_date,
            ", ".join(b.data_classes[:3]),
            "[green]Sim[/green]" if b.is_verified else "[yellow]Não[/yellow]",
        )

    console.print(table)
    raise typer.Exit(2)


if __name__ == "__main__":
    app()