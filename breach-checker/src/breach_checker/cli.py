import asyncio
import getpass
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from breach_checker.checker import check_password, check_email, check_domain_fast

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

@app.command()
def check_domain(
    domain: str = typer.Argument(help="Domínio corporativo (ex: empresa.com)"),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", envvar="HIBP_API_KEY"
    ),
    concurrency: int = typer.Option(20, "--concurrency", "-c"),
) -> None:
    """Verifica todos os emails de um domínio corporativo (usa Go scanner)."""
    if not api_key:
        console.print(
            "[red]Erro: define HIBP_API_KEY no .env ou usa --api-key[/red]"
        )
        raise typer.Exit(1)

    with console.status(f"[bold]A scanear domínio {domain}...[/bold]"):
        try:
            result = check_domain_fast(domain, api_key, concurrency)
        except FileNotFoundError as e:
            console.print(f"[red]Erro: {e}[/red]")
            raise typer.Exit(1)
        except RuntimeError as e:
            console.print(f"[red]Erro: {e}[/red]")
            raise typer.Exit(1)

    console.print(
        Panel(
            f"[bold]Domínio:[/bold] {result['domain']}\n"
            f"[bold]Total Emails:[/bold] {result['total_emails']}\n"
            f"[bold]Comprometidos:[/bold] [red]{result['compromised']}[/red]",
            border_style="blue",
        )
    )

    if result['compromised'] > 0:
        table = Table(title="Emails Comprometidos")
        table.add_column("Email", style="bold")
        table.add_column("Vazamentos")
        
        for r in result['results']:
            if r['breach_count'] > 0:
                table.add_row(
                    r['email'],
                    ", ".join(r['breaches'][:3]),
                )
        
        console.print(table)
        raise typer.Exit(2)


if __name__ == "__main__":
    app()