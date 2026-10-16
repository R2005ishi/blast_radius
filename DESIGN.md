---
name: BlastRadius
description: CVE triage agent console; the graph decides, the model explains, a human signs off.
colors:
  ground: "#0d1117"
  panel: "#151a22"
  elevated: "#1b212b"
  raised: "#222935"
  seam: "#262c36"
  line: "#30363d"
  line-hover: "#3d444d"
  text: "#e6edf3"
  text-soft: "#c9d1d9"
  muted: "#8b949e"
  dim: "#6e7681"
  keyword: "#79c0ff"
  blast-edge: "#4b8ad6"
  string: "#56d364"
  number: "#d2a8ff"
  warning: "#e3b341"
  warning-border: "#5a4a1d"
  warning-wash: "#261f0d"
  destructive: "#ff6b61"
  destructive-border: "#6e2a26"
  destructive-wash: "#2a1414"
  primary: "#1f6feb"
  primary-hover: "#388bfd"
typography:
  headline:
    fontFamily: "JetBrains Mono, ui-monospace, Cascadia Code, Consolas, monospace"
    fontSize: "23px"
    fontWeight: 500
    letterSpacing: "-0.01em"
  title:
    fontFamily: "Lexend, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "18px"
    fontWeight: 500
  body:
    fontFamily: "Lexend, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.55
  body-mono:
    fontFamily: "JetBrains Mono, ui-monospace, Cascadia Code, Consolas, monospace"
    fontSize: "13px"
    fontWeight: 400
    fontFeature: "tnum"
  label:
    fontFamily: "Lexend, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "12px"
    fontWeight: 500
    letterSpacing: "0.08em"
  code:
    fontFamily: "JetBrains Mono, ui-monospace, Cascadia Code, Consolas, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.6
rounded:
  badge: "4px"
  r: "6px"
  pill: "999px"
spacing:
  xs: "6px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  gutter: "18px"
  xl: "20px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "#ffffff"
    rounded: "{rounded.r}"
    padding: "0 16px"
    height: "40px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    rounded: "{rounded.r}"
    padding: "0 16px"
    height: "40px"
  button-secondary-hover:
    backgroundColor: "{colors.elevated}"
  input-question:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.text}"
    rounded: "{rounded.r}"
    padding: "10px 12px"
  panel-header:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.muted}"
    typography: "{typography.label}"
    padding: "12px 18px"
    height: "44px"
  queue-row:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    rounded: "{rounded.r}"
    padding: "7px 10px"
  queue-row-selected:
    backgroundColor: "{colors.elevated}"
  priority-p0:
    backgroundColor: "#b62324"
    textColor: "{colors.text}"
    rounded: "{rounded.badge}"
    padding: "3px 7px"
  priority-p1:
    backgroundColor: "{colors.warning-wash}"
    textColor: "{colors.warning}"
    rounded: "{rounded.badge}"
    padding: "3px 7px"
  priority-p2:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "{rounded.badge}"
    padding: "3px 7px"
  graph-node:
    backgroundColor: "{colors.elevated}"
    textColor: "{colors.text}"
    typography: "{typography.body-mono}"
    rounded: "{rounded.r}"
    padding: "7px 11px"
  graph-node-service:
    backgroundColor: "{colors.elevated}"
    textColor: "{colors.text}"
    rounded: "{rounded.r}"
    padding: "10px 14px"
  code-block:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.text-soft}"
    typography: "{typography.code}"
    rounded: "{rounded.r}"
    padding: "10px 12px"
---

<!-- Impeccable seed key: 5345550a. World: "Dark Developer Console" (catalog id digital-design-canon-dark-first-developer-console), the user-chosen alternate (challenger 2 of the hand), not the assigned roll. Recorded here because the seed is persisted nowhere else. -->

# Design System: BlastRadius

## Overview

**Creative North Star: "The Graphite Console"**

The agent's reasoning is the interface. One graphite console holds the question, the streamed tool steps with the Cypher they ran, the ranked triage queue, the drawn blast path, and the human sign-off. It reads like a code editor and a terminal sharing a desk: dark ground, flat panels split by hairline seams, and colour that appears only when something has a state worth naming.

It is an Operate surface, dense and calm. It is built to be read off a projector in about sixty seconds. Hierarchy comes from mono versus sans, from position in a fixed three-column layout, and from state colour. Size does very little of the work. The confirmed anti-reference is the neon force-graph SOC wallboard: no glow, no free-floating physics graph, no colour used for atmosphere.

**Key Characteristics:**
- Graphite ground with flat panels; depth comes from tone and 1px seams, never from shadow.
- Syntax-highlighting accents carry state only, with one meaning each.
- Lexend for UI prose, JetBrains Mono for ids, Cypher, scores and figures.
- A tight 12/13/15 chrome scale. Larger sizes are kept for the brand, empty-state headings and the two story headings.
- One authored motion: blast edges draw in once.

## Colors

Each accent is a syntax-highlighting colour with one job, set on a near-black GitHub-dark graphite.

### Primary
- **Commit Blue** (primary / primary-hover): fills the action you would commit: Run triage and Approve and file. It is never decoration.
- **Keyword Blue** (keyword): marks selection and focus. It is the focus ring, the selected queue row's border, the exposed-service node's border, step tool names, suggestion icons and Cypher keywords. The caller edges on the canvas use a darker step of this hue (#4b8ad6).

### Secondary
- **Number Purple** (number): scores and figures only. That covers queue scores, the formula operands in the detail calc, and numeric literals in Cypher.
- **String Green** (string): filed, live and fixed. It covers the filed confirmation, the live mode dot, the fix arrow, argument values and string literals.

### Tertiary
- **Signal Amber** (warning, warning-border, warning-wash): P1 and replay. It is used for the P1 badge and action line, the replay mode pill, the replay banner, and the "exposed" tag on caller nodes.
- **Breach Red** (destructive, destructive-border, destructive-wash): P0 and the vulnerable dependency path. It is used for the P0 action line, the CVE and vulnerable-package nodes, the dependency-path edges, HIGH/CRITICAL severity, and error text. The solid P0 badge (#b62324 fill and border, text-colour label) is the only filled red on the page.

### Neutral
- **Graphite Ground** (ground): page ground, the blast canvas, and inset wells (textarea, code blocks, calc).
- **Panel Slate** (panel): the three columns and the top strip.
- **Elevated / Raised** (elevated, raised): hover and selected fills, graph nodes, and the shimmer bar's two tones.
- **Seam** (seam): the 1px gaps between panels, section dividers, and the canvas dot grid.
- **Line / Line Hover** (line, line-hover): control borders at rest and on hover.
- **Text / Text Soft** (text, text-soft): primary copy, and the softer code and reasons copy.
- **Muted** (muted): panel headers, metadata, hints. It gives 5.6:1 on panel and is the lowest tone allowed for readable text.
- **Dim** (dim): inactive indicators only, such as the idle mode dot and the empty priority dash.

### Named Rules
**The State-Only Accent Rule.** Each accent has exactly one meaning: blue means selected or primary, purple a score, green filed, amber P1 or replay, red P0 or the vulnerable path. If a colour cannot name the state it marks, leave the element neutral.

**The Never-Colour-Alone Rule.** Every state colour comes with text: P0/P1/P2 labels, "exposed", "Replay ·", "Approved and filed", and a legend for the edge colours. On a projector the text is what reads.

## Typography

**Display Font:** none (the console has no display tier)
**Body Font:** Lexend (with system-ui, -apple-system, Segoe UI)
**Label/Mono Font:** JetBrains Mono (with ui-monospace, Cascadia Code, Consolas), tabular numerals

**Character:** Lexend gives wide, legible UI prose built for distance reading. JetBrains Mono marks anything the machine produced or a person would copy, such as an id, a query or a number.

### Hierarchy
- **Headline** (mono 500, 23px, -0.01em): only the two story headings, the CVE id in the blast header and the selected service in the detail.
- **Title** (sans 500–600, 18px): the brand wordmark and empty-state headings.
- **Body** (sans 400, 15px, 1.55): steps, answers, reasons, buttons, and service names in the queue (mono 500).
- **Secondary** (13px): metadata, stats, legend, the formula line, mono args and inline code.
- **Label** (sans 500, 12px, 0.08em, uppercase): panel headers and canvas column labels. Code blocks, priority and severity badges, and step numbers also sit at 12px in mono.

### Named Rules
**The Tight Scale Rule.** Chrome stays on 12/13/15. Only the brand and empty states go to 18, and only the two story headings go to 23. The detector's flat-type-hierarchy warning is an accepted exception for this Operate surface. Do not add sizes between steps or above 23.

**The Machine-Text-Is-Mono Rule.** Ids, package@versions, Cypher, scores, counts, keyboard hints and file paths are set in JetBrains Mono. Prose explaining them is set in Lexend.

## Layout

The page is a full-height app shell. A 52px top strip holds the brand, graph counts and the live/replay pill. Below it is a three-column grid: Question and agent steps (330–380px), the blast canvas (fluid), and the triage queue (330–410px). The columns are separated by a 1px seam, made from a `gap: 1px` over the seam colour. Each panel opens with a 44px uppercase header. Panel content uses 18px side padding and 12–16px vertical rhythm. Sections are split by 1px seam rules, not by whitespace alone.

The blast canvas sits on a 1px dot grid at 18px. Its columns run left to right: the dependency path stacked top-down, then the exposed service, then callers by hop, with 52px between columns. The canvas scales down to a 0.6 minimum before it scrolls.

At 1180px or narrower, the grid drops to two columns and the queue spans the full width below. At 820px or narrower, everything is a single column ordered Question, Queue, Blast. The top strip wraps, and the canvas is capped at 70vh.

## Elevation & Depth

The system is flat. No element casts a shadow. Depth comes from tone in this order: ground (inset wells and canvas), then panel, then elevated (nodes, hover, selected), then raised (the shimmer highlight). Separation comes from 1px seams.

### Named Rules
**The Seam-Not-Shadow Rule.** Separate surfaces with a 1px seam or a tonal step, never with a box-shadow or glow.

## Shapes

One gentle radius (6px) is used for controls, nodes, wells and queue rows. Badges and inline code use a tighter 4px. The live/replay mode pill is the only fully round shape (999px), along with its 8px status dot. Borders are 1px solid. The only dashed border is the "blast stays local" note, which marks the absence of callers. Edges are 2px cubic curves, and the vulnerable path is 2.5px.

## Components

### Buttons
- **Shape:** gently rounded (6px), 40px tall, 16px side padding, 15px/500, 18px leading icon.
- **Primary:** Commit Blue fill with white text. It is only used for Run triage and Approve and file. It fills the available row width.
- **Hover / Focus:** a 150ms colour transition to primary-hover. Focus shows a 2px Keyword Blue outline at 2px offset.
- **Secondary:** transparent with a Line border. On hover it fills with elevated and the border shifts to line-hover. Disabled is 50% opacity. While running, the label swaps to a spinning loader with "Agent running…" or "Filing…".

### Chips
- **Priority badges:** mono 600, 12px, 4px radius, 1px border. P0 is solid red. P1 is amber text on an amber wash. P2 is muted text on a line border. "None" shows a dim dash on a seam border.
- **Severity badge:** mono 500, 12px. HIGH and CRITICAL use red on a red wash, MODERATE uses amber, and LOW is muted.
- **Mode pill:** a 999px outline with a status dot. Live is a green dot. Replay turns the border, text and dot amber.

### Cards / Containers
- **Corner Style:** panels are square and fill the grid. Inset wells use 6px.
- **Background:** panel for the columns, ground for wells (textarea, code, calc).
- **Shadow Strategy:** none (see Elevation & Depth).
- **Border:** 1px seam for wells, 1px seam rules between sections.
- **Internal Padding:** 16–18px for panel sections, 10px 12px for wells.

### Inputs / Fields
- **Style:** ground fill, 1px line border, 6px radius, 15px, 10px 12px padding, vertical resize only.
- **Focus:** the border turns Keyword Blue and the outline is removed. Hover moves the border to line-hover.
- **Error:** red 13px text below the row, announced with role="alert".

### Navigation
The top strip is not navigation. It reports state. The brand mark is a red dot with three fading blue arcs. Stats are muted 13px text with mono values, set off by a seam rule. The mode pill sits at the right.

### Agent Step (signature)
Each numbered step shows the tool name in mono Keyword Blue. Arguments follow in mono muted with values in String Green, then a one-line Lexend summary. Below that is a collapsible "Cypher · n queries" disclosure with a rotating chevron, holding syntax-highlighted code blocks. Steps enter once with a 4px rise over 250ms.

### Triage Queue Row (signature)
Each row is a four-column grid: priority badge, mono service name, muted metadata, and a right-aligned purple score in a 52px column. Hover fills with elevated. The selected row (aria-pressed) adds a Keyword Blue border. Selecting a row redraws the blast and the detail.

### Blast Graph Node and Edge (signature)
Nodes are mono 13px on elevated with a 1px line border, 6px radius, and a muted 12px sub-line. The CVE node uses the red border and red wash. The vulnerable package uses a red border. The exposed service uses a Keyword Blue border on elevated at 15px/500. Caller nodes that have a draft are buttons and get a blue border on hover. Edges draw in once using stroke-dashoffset at 550ms with cubic-bezier(.2,.8,.2,1). The dependency path draws first, staggered by column, and callers follow. Under prefers-reduced-motion the edges render static.

## Do's and Don'ts

### Do:
- **Do** keep every accent tied to its one state: blue selected/primary, purple score, green filed, amber P1/replay, red P0/vulnerable path.
- **Do** pair every state colour with a text label or legend entry.
- **Do** set ids, Cypher, scores and paths in JetBrains Mono with tabular numerals.
- **Do** stay on the 12/13/15 chrome scale. Use 18 for the brand and empty states, and 23 only for a story heading.
- **Do** separate surfaces with 1px seams and tonal steps.
- **Do** keep the edge draw-in as the single authored motion and respect prefers-reduced-motion.
- **Do** label replays as replays (amber pill and banner) wherever live data could be assumed.

### Don't:
- **Don't** add box-shadows, glows, or gradients for atmosphere. The only gradient is the shimmer progress bar.
- **Don't** build a neon force-graph SOC wallboard. The blast reads left to right in columns, not as floating physics.
- **Don't** use an accent decoratively or give one accent a second meaning.
- **Don't** use dim (#6e7681) for readable text. It is for inactive indicators only.
- **Don't** introduce type sizes between the scale steps or a display tier above 23px.
