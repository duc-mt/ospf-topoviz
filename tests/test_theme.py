"""Light and dark themes: the static Graphviz picture (--theme) and the colour tokens of the explorer page."""

from __future__ import annotations

import re
import shutil

import pytest
import yaml

import main
from src.explorer import TEMPLATE, build_scene, render_html
from src.graph_engine import TopologyDiff
from src.visualizer import (
    COLOR_NORMAL,
    DARK,
    LIGHT,
    PALETTES,
    THEMES,
    Palette,
    TopologyVisualizer,
    VisualizationError,
    VisualOptions,
    adjacency_color,
)
from tests.explorer_fixture import realistic

P = "10.255.255."
NAMED = {"white": "#ffffff", "black": "#000000"}


def luminance(color: str) -> float:
    h = NAMED.get(color, color).lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))

    def lin(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def contrast(a: str, b: str) -> float:
    """WCAG contrast ratio (1 = none, 21 = black on white)."""
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def graph_with_states():
    g = realistic()
    g[P + "5"]["net-10.130.240.1"]["nbr_state"] = "ExStart"
    g[P + "11"]["net-10.130.240.1"]["nbr_state"] = "Init"
    return g


def dot(theme: str | None, graph=None, diff=None) -> str:
    options = VisualOptions() if theme is None else VisualOptions(theme=theme)
    return (
        TopologyVisualizer(options=options)
        .build_digraph(graph or graph_with_states(), diff or TopologyDiff())
        .source
    )


# ===================================================== options and palettes
def test_light_stays_the_default_so_existing_output_is_unchanged():
    assert VisualOptions().theme == "light" and VisualOptions().theme_explicit is False
    assert TopologyVisualizer().palette is LIGHT
    assert THEMES == ("light", "dark") and set(PALETTES) == {"light", "dark"}


def test_the_theme_can_come_from_the_settings_file():
    options = VisualOptions.from_settings({"theme": "Dark"})
    assert options.theme == "dark" and options.theme_explicit is True
    assert VisualOptions.from_settings({}).theme_explicit is False


def test_an_unknown_theme_is_rejected():
    with pytest.raises(VisualizationError, match="theme"):
        VisualOptions.from_settings({"theme": "solarized"})


def test_both_palettes_define_every_colour_and_the_dark_one_is_really_different():
    fields = Palette.__dataclass_fields__
    for palette in (LIGHT, DARK):
        assert (
            all(getattr(palette, name) for name in fields if name != "background")
            and palette.name in THEMES
        )
    assert LIGHT.background is None and DARK.background == "#0B1324"
    assert (DARK.edge, DARK.text) == ("#94A3B8", "#E6EDF7")
    assert LIGHT.edge == COLOR_NORMAL


def test_the_dark_palette_has_enough_contrast():
    bg = DARK.background
    assert contrast(DARK.text, bg) >= 7 and contrast(DARK.edge_text, bg) >= 7
    assert (
        contrast(DARK.edge, bg) >= 4.5 and contrast(DARK.muted, bg) >= 4.5
    )  # links and area outlines
    for line in (
        DARK.added,
        DARK.removed,
        DARK.changed,
        DARK.full,
        DARK.two_way,
        DARK.stuck,
        DARK.down,
        DARK.path,
        DARK.warn,
    ):
        assert contrast(line, bg) >= 4.5, line
    assert contrast(DARK.router_text, DARK.fill_router) >= 4.5
    assert contrast(DARK.network_text, DARK.fill_network) >= 4.5
    assert contrast(DARK.unresolved_text, DARK.fill_unresolved) >= 4.5
    assert contrast(DARK.removed, DARK.fill_removed) >= 4.5


def test_adjacency_colours_follow_the_palette():
    assert adjacency_color("Full") == LIGHT.full  # the old call still works
    assert (
        adjacency_color("Full", DARK) == DARK.full
        and adjacency_color("Init", DARK) == DARK.down
    )
    assert (
        adjacency_color("ExStart", DARK)
        == adjacency_color("Loading", DARK)
        == DARK.stuck
    )
    assert adjacency_color(None, DARK) is None


# ==================================================================== graphviz
def test_dark_draws_on_the_dark_canvas_with_light_lines_and_text():
    source = dot("dark")
    assert 'bgcolor="#0B1324"' in source
    assert source.count('color="#94A3B8"') >= 10  # ordinary links and node outlines
    assert 'fontcolor="#E6EDF7"' in source  # title, link labels and node text
    assert 'fontcolor="black"' not in source and 'fontcolor="white"' not in source


def test_the_title_and_the_legend_text_are_light_in_dark_mode():
    assert re.search(
        r'fontcolor="#E6EDF7"\s+fontname="Helvetica"|label=.*fontcolor="#E6EDF7"',
        dot("dark"),
        re.S,
    )


def test_light_has_no_canvas_colour_and_keeps_the_classic_colours():
    source = dot("light")
    assert (
        "bgcolor" not in source and "#0B1324" not in source and "#94A3B8" not in source
    )
    assert f'color="{COLOR_NORMAL}"' in source


def test_the_default_is_identical_to_light():
    assert dot(None) == dot("light")


def test_stuck_links_use_the_dark_adjacency_colours():
    source = dot("dark")
    assert DARK.stuck in source and DARK.down in source  # ExStart and Init links
    assert LIGHT.stuck not in source and LIGHT.down not in source


def test_dark_node_fills_differ_from_light_and_text_stays_readable():
    dark, light = dot("dark"), dot("light")
    assert (
        DARK.fill_network in dark
        and DARK.fill_router in dark
        and DARK.fill_unresolved in dark
    )
    assert DARK.fill_network not in light


def test_removed_and_added_elements_use_the_dark_status_colours():
    diff = TopologyDiff(
        baseline_available=True,
        added_nodes=[{"id": P + "20", "type": "router"}],
        removed_nodes=[{"id": "10.9.9.9", "type": "router", "areas": ["0.0.0.0"]}],
        removed_edges=[
            {
                "source": "10.9.9.9",
                "target": P + "5",
                "metric": 4,
                "link_type": "point-to-point",
                "area": "0.0.0.0",
            }
        ],
    )
    source = dot("dark", diff=diff)
    assert (
        DARK.removed in source and DARK.fill_removed in source and DARK.added in source
    )


def test_a_traced_path_is_drawn_in_the_dark_path_colour():
    graph = graph_with_states()
    source = (
        TopologyVisualizer(options=VisualOptions(theme="dark"))
        .build_digraph(
            graph, TopologyDiff(), highlight={frozenset((P + "6", "net-10.130.240.1"))}
        )
        .source
    )
    assert DARK.path in source


@pytest.mark.skipif(shutil.which("dot") is None, reason="Graphviz is not installed")
def test_a_dark_image_is_really_rendered_dark(tmp_path):
    viz = TopologyVisualizer(
        output_path=tmp_path / "t.svg", options=VisualOptions(theme="dark")
    )
    svg = viz.render(graph_with_states(), TopologyDiff()).read_text(encoding="utf-8")
    assert re.search(r'<polygon fill="#0b1324"', svg, re.I)
    light = (
        TopologyVisualizer(output_path=tmp_path / "l.svg")
        .render(graph_with_states(), TopologyDiff())
        .read_text(encoding="utf-8")
    )
    assert not re.search(r'<polygon fill="#0b1324"', light, re.I)


# ========================================================================= cli
@pytest.fixture
def cli(monkeypatch, tmp_path):
    from tests.test_visibility import HOST, FakeNetwork, sample  # noqa: PLC0415

    outputs = {
        "router": sample("router_lsdb.txt"),
        "network": sample("network_lsdb.txt"),
        "neighbors": sample("neighbors.txt"),
        "routes": sample("routes.txt"),
    }
    monkeypatch.setattr(main, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr("src.poller.ConnectHandler", FakeNetwork({HOST: outputs}))
    seen = []
    real = TopologyVisualizer.render

    def render(self, graph, diff, highlight=None, **kw):
        seen.append(
            (
                self.output_path.suffix,
                self.options.theme,
                self.options.theme_explicit,
                self.palette.name,
            )
        )
        return (
            real(self, graph, diff, highlight, **kw)
            if self.interactive
            else self.output_path
        )

    monkeypatch.setattr(main.TopologyVisualizer, "render", render)

    def run(*args, visualization=None):
        config = tmp_path / "settings.yaml"
        settings = {
            "device": {
                "host": HOST,
                "username": "u",
                "password": "p",
                "device_type": "vyos",
            }
        }
        if visualization is not None:
            settings["visualization"] = visualization
        config.write_text(yaml.safe_dump(settings))
        return main.main(["--config", str(config), "--dry-run", *args])

    run.seen = seen
    return run


def test_theme_flag_selects_the_dark_picture(cli, tmp_path):
    assert cli("--output", str(tmp_path / "t.png"), "--theme", "dark") == main.EXIT_OK
    assert cli.seen[0] == (".png", "dark", True, "dark")
    assert cli.seen[1][0] == ".html" and cli.seen[1][1] == "dark"


def test_without_the_flag_the_picture_stays_light(cli, tmp_path):
    cli("--output", str(tmp_path / "t.png"))
    assert cli.seen[0] == (".png", "light", False, "light")
    assert cli.seen[1][0] == ".html" and cli.seen[1][1] == "light"


def test_the_settings_file_can_set_the_theme_and_the_flag_overrides_it(cli, tmp_path):
    cli("--output", str(tmp_path / "t.png"), visualization={"theme": "dark"})
    assert cli.seen[0][1:] == ("dark", True, "dark")
    cli(
        "--output",
        str(tmp_path / "t.png"),
        "--theme",
        "light",
        visualization={"theme": "dark"},
    )
    assert cli.seen[-2][1:] == ("light", True, "light")


def test_the_flag_rejects_other_values(capsys):
    with pytest.raises(SystemExit):
        main.parse_args(["--theme", "solarized"])


def test_theme_reaches_the_explorer_written_next_to_the_image(cli, tmp_path, monkeypatch):
    html_target = tmp_path / "x.html"
    monkeypatch.setattr(main, "OUTPUT_HTML", html_target)
    cli(
        "--output",
        str(tmp_path / "t.png"),
        "--theme",
        "dark",
    )
    assert [s[0] for s in cli.seen] == [".png", ".html"] and cli.seen[1][1] == "dark"
    assert 'data-theme-default="dark"' in html_target.read_text(
        encoding="utf-8"
    )



# ====================================================== explorer page: tokens
LIGHT_TOKENS = {
    "--bg": "#f8fafc",
    "--panel": "#ffffff",
    "--panel2": "#f1f5f9",
    "--line": "#e2e8f0",
    "--text": "#0f172a",
    "--muted": "#64748b",
    "--dot": "#cbd5e1",
}


def token_block(css: str, theme: str) -> str:
    return re.search(rf'\[data-theme="{theme}"\]\{{(.*?)\}}', css, re.S).group(1)


def page_css() -> str:
    return re.search(
        r"<style>(.*?)</style>", TEMPLATE.read_text(encoding="utf-8"), re.S
    ).group(1)


def tokens(block: str) -> dict[str, str]:
    return dict(re.findall(r"(--[\w-]+):(#[0-9a-fA-F]{3,8})", block))


def test_the_light_theme_uses_the_specified_palette():
    light = tokens(token_block(page_css(), "light"))
    for name, value in LIGHT_TOKENS.items():
        assert light[name] == value, name


def test_the_dark_theme_keeps_the_current_palette():
    assert tokens(token_block(page_css(), "dark"))["--bg"] == "#0b1324"


def test_both_themes_define_exactly_the_same_tokens():
    css = page_css()
    assert set(tokens(token_block(css, "dark"))) == set(
        tokens(token_block(css, "light"))
    )


def test_no_colour_is_hard_coded_outside_the_token_blocks():
    css = page_css()
    for theme in ("dark", "light"):
        css = css.replace(token_block(css, theme), "")
    assert re.findall(r"#[0-9a-fA-F]{3,8}\b", css) == []


def test_the_page_sets_its_theme_before_the_first_paint():
    page = TEMPLATE.read_text(encoding="utf-8")
    head = page.split("</head>")[0]
    assert (
        "ospf-explorer:theme" in head
        and "prefers-color-scheme: light" in head
        and "data-theme-default" in head
    )
    assert '<html lang="en" data-theme="dark"' in page


def test_the_header_has_a_theme_button():
    page = TEMPLATE.read_text(encoding="utf-8")
    assert re.search(r'<header id="top">.*id="b-theme".*</header>', page, re.S)


def test_the_page_tells_the_script_its_starting_theme():
    scene = build_scene(realistic(), TopologyDiff())
    assert scene["meta"][
        "theme"
    ] == "auto" and 'data-theme-default="auto"' in render_html(scene)
    scene["meta"]["theme"] = "light"
    assert 'data-theme-default="light"' in render_html(scene)
    scene["meta"]["theme"] = "<script>"
    assert 'data-theme-default="auto"' in render_html(
        scene
    )  # never anything but the three known values


def test_the_scene_meta_follows_an_explicit_theme():
    scene = build_scene(
        realistic(), TopologyDiff(), VisualOptions(theme="dark", theme_explicit=True)
    )
    assert scene["meta"]["theme"] == "dark"
    assert (
        build_scene(realistic(), TopologyDiff(), VisualOptions(theme="dark"))["meta"][
            "theme"
        ]
        == "auto"
    )


# ================================================== explorer page: SVG colours
def palettes() -> dict[str, dict[str, str]]:
    block = re.search(
        r"var PAL = \{.*?\n\};", TEMPLATE.read_text(encoding="utf-8"), re.S
    ).group(0)
    out = {}
    for theme in ("dark", "light"):
        section = block.split(f"{theme}: {{")[1].split("}")[0]
        out[theme] = dict(re.findall(r"(\w+): '(#[0-9a-fA-F]{6})'", section))
    return out


@pytest.mark.parametrize("theme, bg", [("dark", "#0b1324"), ("light", "#f8fafc")])
def test_svg_text_is_legible_in_both_themes(theme, bg):
    c = palettes()[theme]
    assert (
        contrast(c["text"], c["router"]) >= 4.5
        and contrast(c["subText"], c["router"]) >= 4.5
    )
    assert contrast(c["dark"], c["net"]) >= 4.5  # network text on its fill
    assert contrast(c["pillText"], c["pillBg"]) >= 7  # cost and interface badges
    assert contrast(c["areaLabel"], bg) >= 4.5
    assert c["exportBg"].lower() == bg


@pytest.mark.parametrize("theme, bg", [("dark", "#0b1324"), ("light", "#f8fafc")])
def test_svg_lines_stand_out_from_the_canvas_in_both_themes(theme, bg):
    c = palettes()[theme]
    assert contrast(c["link"], bg) >= 4.5
    for name in (
        "oneway",
        "added",
        "removed",
        "changed",
        "full",
        "twoway",
        "stuck",
        "down",
        "path",
        "focus",
        "area",
    ):
        assert contrast(c[name], bg) >= 3.0, (
            name
        )  # WCAG 1.4.11: graphical objects need 3:1


def test_the_two_svg_palettes_have_the_same_keys():
    both = palettes()
    assert set(both["dark"]) == set(both["light"])


def edge_lines(source: str) -> list[str]:
    return [
        line
        for line in source.splitlines()
        if " -- " in line and "dotted" not in line and "dashed" not in line
    ]


def test_ordinary_links_and_their_labels_follow_the_palette():
    dark = [line for line in edge_lines(dot("dark")) if 'color="#94A3B8"' in line]
    assert len(dark) >= 5 and all(
        'fontcolor="#E6EDF7"' in line for line in dark
    )  # label text matches the line
    assert not [line for line in edge_lines(dot("dark")) if COLOR_NORMAL in line]
    light = [
        line for line in edge_lines(dot("light")) if f'color="{COLOR_NORMAL}"' in line
    ]
    assert len(light) >= 5 and all(
        "#94A3B8" not in line for line in edge_lines(dot("light"))
    )


def test_the_page_head_script_resolves_the_theme_on_its_own():
    head = TEMPLATE.read_text(encoding="utf-8").split("</head>")[0]
    assert (
        "pref = root.getAttribute('data-theme-default') || 'auto'" in head
    )  # the page default when nothing is saved
    assert "pref === 'auto' && window.matchMedia" in head  # "auto" asks the system
