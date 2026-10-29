# CYBR_ --- Website UI/UX Design Specification

> **Design direction:** Cyber Brutalism --- raw, technical,
> high-contrast, system-driven, unapologetically functional.
>
> **Reference:** User-provided screenshot of a dark portfolio/creative
> studio website featuring acid-lime accents, monospaced labels, a
> wireframe/glitch 3D head, technical HUD elements, project cards,
> system status, and hazard-stripe footer details.
>
> **Primary objective:** Recreate the visual language and layout logic
> of the reference while building a responsive, accessible,
> production-quality website. Treat the screenshot as the design source
> of truth for aesthetics, not as a pixel-perfect fixed canvas.

------------------------------------------------------------------------

## 1. Design Principles

1.  **Function over decoration.** Every element should feel like part of
    a useful interface, dashboard, terminal, or technical instrument.
2.  **High contrast, limited palette.** Near-black surfaces and
    off-white text are punctuated by a single acid-lime accent.
3.  **Visible structure.** Use thin rules, numbered sections, modular
    grids, alignment lines, corner marks, and compact metadata.
4.  **Typography as architecture.** Large condensed display headings
    create impact; monospaced text carries navigation, labels, system
    values, and supporting copy.
5.  **Controlled visual noise.** Glitch, scanline, grain, and
    data-overlay effects should be subtle and purposeful. Never
    sacrifice legibility.
6.  **Hard edges.** Prefer square corners, crisp outlines, thin borders,
    and geometric blocks over soft shadows, gradients, or rounded cards.
7.  **Responsive, not merely scaled.** Recompose the grid for small
    screens rather than shrinking the desktop composition.
8.  **Motion communicates state.** Animations should suggest scanning,
    loading, system activity, or navigation---not add motion without
    meaning.

## 2. Brand and Art Direction

-   **Brand label:** `CYBR_` (replace with the actual brand name if
    needed).
-   **Personality:** Experimental, technical, precise, uncompromising,
    digital-native.
-   **Keywords:** Cyber brutalism, industrial interface, terminal,
    glitch, grid, signal, system status, raw digital craft.
-   **Avoid:** Generic SaaS styling, pastel gradients, glassmorphism,
    oversized rounded pills, excessive drop shadows, stock corporate
    illustrations, and large areas of decorative empty space that break
    the reference's dense technical rhythm.
-   **Composition:** Dense but ordered. The page can feel complex, but
    alignment and spacing must remain deliberate.

## 3. Color Tokens

Use CSS custom properties so the palette is centrally managed.

  --------------------------------------------------------------------------
  Token                      Suggested value         Usage
  -------------------------- ----------------------- -----------------------
  `--color-bg`               `#070807`               Main page background

  `--color-surface`          `#0D0F0D`               Cards, panels, inset
                                                     regions

  `--color-surface-raised`   `#141714`               Hovered panels and
                                                     highlighted blocks

  `--color-lime`             `#D7FF35`               Primary CTA, active
                                                     markers, highlights

  `--color-lime-muted`       `#A8C92A`               Secondary lime details
                                                     and low-emphasis data

  `--color-text`             `#F2F2ED`               Main headings and body
                                                     text

  `--color-text-muted`       `#A2A59A`               Supporting copy and
                                                     inactive metadata

  `--color-text-dim`         `#686D64`               Decorative labels; do
                                                     not use for essential
                                                     text

  `--color-border`           `#343832`               Panel outlines and
                                                     separators

  `--color-border-strong`    `#62685B`               Focused/active
                                                     structural edges

  `--color-danger`           `#FF6B5E`               Optional errors only;
                                                     use sparingly
  --------------------------------------------------------------------------

### Color rules

-   The page should read as approximately **80--90% dark surface**, with
    lime reserved for high-value actions and small data accents.
-   Use off-white rather than pure white for most text.
-   Lime blocks may use dark text for clear contrast.
-   Avoid introducing extra accent colors unless a functional status
    requires one.
-   Do not rely on color alone to communicate status; pair it with text
    or an icon.

## 4. Typography

Use a condensed display face and a legible monospace face. Suitable
web-font pairings include **Barlow Condensed** or **Oswald** for display
headings and **IBM Plex Mono** or **Space Mono** for interface copy. Use
a system fallback if fonts cannot load.

  ------------------------------------------------------------------------------------------------
  Role                           Desktop guideline                Mobile guideline Style
  --------------- -------------------------------- ------------------------------- ---------------
  Hero heading      `clamp(3.5rem, 6.5vw, 5.8rem)`   `clamp(2.8rem, 13vw, 4.2rem)` Condensed,
                                                                                   uppercase,
                                                                                   bold, tight
                                                                                   line-height

  Section heading                       `1.5–2rem`                   `1.35–1.7rem` Uppercase,
                                                                                   condensed or
                                                                                   mono

  Card title                        `1rem–1.15rem`                          `1rem` Monospace,
                                                                                   uppercase

  Body copy                             `0.9–1rem`                        `0.9rem` Monospace or
                                                                                   neutral
                                                                                   sans-serif

  Navigation                        `0.72–0.82rem`                       `0.75rem` Monospace,
                                                                                   uppercase

  Technical                         `0.62–0.75rem`                  `0.65–0.72rem` Monospace,
  metadata                                                                         uppercase,
                                                                                   tracked

  Buttons                           `0.75–0.85rem`                  `0.75–0.85rem` Monospace,
                                                                                   bold, uppercase
  ------------------------------------------------------------------------------------------------

Typography requirements: - Hero heading line-height: approximately
`0.88–0.98`. - Use tracking of `0.02em–0.08em` for small uppercase
labels, but avoid excessive tracking in long body copy. - Keep body copy
line-length near 45--65 characters where possible. - Use tabular
numerals for system metrics, timestamps, and coordinates. - Do not use
the display font for long paragraphs.

## 5. Layout and Spacing

-   **Desktop content width:** Full-width editorial layout with a
    consistent outer gutter of `clamp(1rem, 4.5vw, 4rem)`.
-   **Grid:** 12-column desktop grid; 6-column tablet grid; 4-column
    mobile grid, with content recomposed at breakpoints.
-   **Spacing scale:** 4, 8, 12, 16, 24, 32, 48, 64, 96 px.
-   **Borders:** Mostly 1px solid rules. Use thicker borders only to
    distinguish major regions.
-   **Corners:** Square by default (`border-radius: 0`). Any exception
    should be small and functional.
-   **Section separators:** Use full-width horizontal rules to establish
    the stacked, modular structure.
-   **Decorative interface details:** Add small section IDs such as
    `/01`, `/02`, crosshair marks, tiny status labels, and edge markers
    sparingly and consistently.

Recommended breakpoints: - `>= 1200px`: full desktop composition. -
`768–1199px`: compressed navigation and rebalanced columns. - `< 768px`:
single-column content, compact header, stacked hero, horizontally
scrollable or two-column project grid as appropriate. - `< 420px`:
reduce metadata density, keep CTAs full-width where useful, and prevent
long technical labels from overflowing.

## 6. Page Structure

Build the page in the following order, matching the reference's visual
rhythm.

### 6.1 Top Navigation

**Appearance** - A narrow, full-width top bar with a thin bottom
border. - Left: lime brand block with a small geometric/glitch-style
symbol and `CYBR_` wordmark. - Center: compact links --- Work, Services,
About, Labs, Contact --- separated by small plus signs or understated
markers. - Right: a compact system-time panel and a lime
`START A PROJECT ↗` CTA. - Navigation labels are small, uppercase,
monospaced, and horizontally aligned.

**Behavior** - Brand links to the top of the page. - Navigation links
scroll to the corresponding sections. - Active/hover states use lime
text or a subtle lime marker. - The time display may show the visitor's
local time if implemented accurately; otherwise use a static label. Do
not fabricate a live server time. - On mobile, collapse links behind an
accessible menu button or show a compact horizontally scrollable nav.
Keep the brand and primary CTA accessible.

### 6.2 Hero / Intro (`/01`)

**Desktop composition** - Two-column layout, approximately 45% text and
55% visual. - Left panel: large stacked heading, short lime-tinted
statement, concise supporting paragraph, and two actions. - Right panel:
dramatic monochrome 3D wireframe head or abstract digital sculpture,
surrounded by grid lines, coordinate readouts, scan marks, small lime
blocks, and technical annotations. - The hero is framed by thin borders
and should feel like a technical display or art-direction viewport.

**Suggested content structure** - Eyebrow:
`DIGITAL STUDIO / SYSTEM 01` - H1: `CYBER BRUTALISM` - Statement:
`THE FUTURE ISN'T MINIMAL. IT'S SYSTEMATIC.` - Description:
`Raw digital experiences built with precision, experimentation, and functional intent.` -
Primary CTA: `EXPLORE WORK ↗` - Secondary CTA: `VIEW MANIFESTO`

**Visual requirements** - Use a high-quality 3D render, locally hosted
asset, or custom-created abstract wireframe sculpture. Keep it
monochrome with controlled lime interference. - Overlay effects should
be layered above the visual, not obscure the subject or text. - Use CSS
grid, pseudo-elements, SVG, or canvas for crosshairs and fine technical
lines. - Add a small progress/readout label only if it reflects real
animation or meaningful content. If simulated, clearly treat it as
decorative rather than operational. - Avoid using an unlicensed image or
assuming an external image URL will always work.

**Mobile behavior** - Stack text above visual. - Reduce decorative
overlays and hide nonessential coordinates. - Keep the H1 and primary
CTA visible early. - Use a stable image aspect ratio to avoid layout
shifts.

### 6.3 Core Principles (`/02`)

-   Full-width section with a section number and title.
-   Five equal desktop columns, each containing a small line icon or
    geometric symbol, a short uppercase title, and a compact
    description.
-   Use vertical separators or spacing to define columns; retain a thin
    horizontal rule above and below.

Principles and sample copy: 1. **FUNCTION OVER FORM** ---
`Design is built to serve. Nothing more.` 2. **SYSTEMS THINKING** ---
`Grids. Modules. Data. Everything is connected.` 3. **DIGITAL
AESTHETICS** --- `Glitch, noise, scanlines, and hardware vibes.` 4.
**BOLD CONTRAST** --- `High contrast. Harsh color. No soft tones.` 5.
**RAW & AUTHENTIC** ---
`No fluff. No polish for its own sake. No compromise.`

Responsive behavior: - Tablet: 2--3 columns depending on available
width. - Mobile: stack into compact rows or a two-column grid with
readable descriptions. - Icons should be consistent in stroke weight and
visual complexity.

### 6.4 Selected Work (`/03`)

-   Section heading aligned with the same numbering system.
-   Four project cards on desktop in a single row.
-   Each card uses a bordered image region, project title, category
    label, and an arrow/link affordance.
-   Keep image treatment monochrome, high contrast, grainy, abstract, or
    technical. Use lime in selected areas rather than tinting every
    image.
-   Cards should be rectangular, with minimal rounding and no soft card
    shadows.

Suggested sample projects: - `DATA_PORTAL` --- Dashboard Design -
`NEURAL_NET` --- AI Platform - `VOID_SYSTEM` --- Branding - `GRIDLINE`
--- Web Experience

**Interaction** - The whole card may be clickable if it has a clear
destination. - Hover: image subtly scales or shifts, a lime
border/marker appears, and the arrow moves a few pixels. - Keyboard
focus: a clearly visible lime outline. - Provide meaningful alt text for
informative images; use empty alt text for purely decorative images. -
Do not make cards appear interactive unless they actually navigate or
open details.

**Responsive behavior** - Desktop: 4 columns. - Tablet: 2 columns. -
Mobile: 1 column or a swipeable carousel with keyboard-accessible
controls. Prefer a simple grid when it is easier to browse.

### 6.5 Lower Information Panels (`/04–/06`)

Use three adjacent bordered panels on desktop, with aligned headings and
consistent padding.

**Panel A --- Join the Resistance (`/04`)** - Short heading, one compact
paragraph, and a lime CTA such as `LET'S BUILD ↗`. - CTA navigates to
the contact/project inquiry section.

**Panel B --- System Status (`/05`)** - Compact metrics such as CPU
usage, memory, uptime, and network status. - Render as simple labeled
rows with thin horizontal bars and aligned numeric values. - If metrics
are illustrative, label them as demo/system-style visuals and do not
imply that they report real infrastructure. - Use accessible text values
alongside visual bars; do not rely on bars alone. - A final outlined
status strip may read `ALL SYSTEMS OPERATIONAL` only if it is clearly
decorative or the status is actually verified.

**Panel C --- Subscribe to Signal (`/06`)** - Short explanation of the
newsletter or update feed. - Email input and lime subscribe button. -
Include visible labels, input validation, loading state, success
confirmation, and useful error messaging. - Do not display a success
state until the form has actually been submitted successfully. - If no
newsletter backend exists yet, provide a non-deceptive demo state or
connect a real service before launch.

Responsive behavior: - Desktop: three columns. - Tablet: two columns
with the remaining panel spanning the row if appropriate. - Mobile:
stack all panels vertically.

### 6.6 Footer

-   Thin top border separating it from the content.
-   Left: brand mark, copyright, and concise legal line.
-   Middle: navigation and resource link groups.
-   Right: social links and a compact global-node/world-map visual.
-   Bottom edge: lime/black diagonal hazard stripes and a terminal-style
    status message such as `> ACCESS GRANTED_`.
-   Keep the footer visually dense but well aligned; ensure links remain
    legible and tappable.
-   On mobile, stack footer groups and simplify or remove the world map
    if it adds clutter.

## 7. Components and States

### Buttons

-   **Primary:** lime background, dark text, square corners, compact
    uppercase mono label, arrow icon where useful.
-   **Secondary:** transparent/dark background, off-white text, subtle
    border or no border.
-   Hover: small color inversion or stronger outline; avoid large scale
    changes.
-   Active: slight pressed-state offset or background shift.
-   Focus-visible: high-contrast outline with a small offset.
-   Disabled: muted colors and a clear disabled state.

### Links

-   Use off-white by default and lime for hover/focus/active.
-   Include underlines where they help distinguish inline links from
    plain text.
-   External links should be identifiable and open according to the
    site's navigation policy.

### Inputs

-   Dark background, 1px border, off-white text, square corners.
-   Visible label above or beside the input; placeholder text must not
    be the only label.
-   Focus state: lime border or outline.
-   Error state: concise message plus non-color indicator.
-   Ensure mobile inputs do not trigger awkward zoom; use a sufficiently
    large font size.

### Cards and panels

-   Dark surface, thin border, consistent inner padding.
-   Avoid shadows and rounded-card conventions.
-   Hover feedback should be subtle and consistent.
-   Use separators and small metadata labels to preserve the industrial
    interface style.

### Icons and technical decorations

-   Use one consistent icon family or custom SVG set.
-   Prefer geometric line icons, crosshairs, plus signs, arrows, grids,
    and small data marks.
-   Decorative symbols should be hidden from assistive technology.
-   Do not use text glyphs as the only way to convey a functional icon's
    meaning.

## 8. Motion and Effects

Motion should be restrained and purposeful.

-   **Navigation:** quick color/marker transition.
-   **Project cards:** subtle image movement and border emphasis.
-   **Hero visual:** optional slow scanline, light glitch flicker, or
    floating technical markers.
-   **System bars:** animate only when there is a meaningful load or
    state change.
-   **Page entry:** optional short fade/translate effect, without
    delaying content visibility.
-   **Transitions:** typically `120–220ms` for UI feedback; longer
    ambient animation should be slow and low contrast.

Respect `prefers-reduced-motion: reduce`: - Disable glitch flicker,
parallax, looping animations, and nonessential motion. - Keep all
content and interactions fully available without animation. - Avoid
rapid flashes or strobing effects.

## 9. Accessibility

-   Meet WCAG 2.2 AA contrast targets wherever practical, especially for
    body text and controls.
-   Use semantic landmarks: `header`, `nav`, `main`, section headings,
    and `footer`.
-   Maintain a logical heading hierarchy with one primary H1.
-   All interactive elements must be keyboard operable.
-   Provide visible focus indicators; do not remove outlines without a
    replacement.
-   Use accessible names for icon-only buttons and menu controls.
-   Associate form fields with labels and announce validation/success
    messages appropriately.
-   Ensure touch targets are ideally at least 44 × 44 CSS pixels.
-   Do not communicate errors, status, or selection through color alone.
-   Provide alt text for meaningful imagery and hide purely decorative
    overlays from screen readers.
-   Test text zoom and narrow viewports for overflow.

## 10. Responsive Acceptance Criteria

### Desktop

-   The header remains compact and aligned.
-   Hero text and visual occupy balanced columns.
-   Principles display as five columns.
-   Selected work displays as four cards.
-   The three lower panels align on a shared grid.
-   Fine borders and metadata remain crisp without making the page feel
    cluttered.

### Tablet

-   No horizontal page overflow.
-   Navigation reduces gracefully.
-   Hero composition remains balanced or stacks when the available width
    requires it.
-   Principles, cards, and information panels reflow without cramped
    text.

### Mobile

-   No horizontal page overflow at 320 CSS pixels and above.
-   Hero heading wraps intentionally without splitting words awkwardly.
-   Primary CTA is easy to reach and tap.
-   Decorative HUD elements reduce in number.
-   Cards and panels become readable stacked blocks.
-   Footer groups stack with comfortable spacing.
-   Body text remains readable without pinch-zoom.

## 11. Technical Implementation Guidance

-   Implement the design with reusable components rather than a single
    monolithic page.
-   Suggested component tree:
    -   `SiteHeader`
    -   `HeroSection`
    -   `TechnicalVisual`
    -   `PrinciplesSection`
    -   `PrincipleItem`
    -   `SelectedWorkSection`
    -   `ProjectCard`
    -   `InfoPanels`
    -   `SystemStatusPanel`
    -   `NewsletterForm`
    -   `SiteFooter`
    -   `HazardStripe`
-   Keep colors, spacing, type sizes, and breakpoints in design tokens.
-   Use CSS Grid for the major layouts and Flexbox for aligned component
    internals.
-   Prefer SVG/CSS for crisp geometric HUD decorations; use canvas only
    if the visual complexity genuinely needs it.
-   Optimize hero and project images; use modern formats and explicit
    dimensions/aspect ratios.
-   Lazy-load below-the-fold project imagery.
-   Avoid shipping heavy animation libraries for simple CSS effects.
-   Ensure all navigation and CTAs have real destinations or clear
    in-page behavior.
-   Do not invent working backend features. Mark unavailable
    functionality as a prototype or implement the integration.
-   Keep content separate from presentation where practical so project
    names and copy can be changed easily.

## 12. Suggested CSS Tokens

``` css
:root {
  color-scheme: dark;

  --color-bg: #070807;
  --color-surface: #0d0f0d;
  --color-surface-raised: #141714;
  --color-lime: #d7ff35;
  --color-lime-muted: #a8c92a;
  --color-text: #f2f2ed;
  --color-text-muted: #a2a59a;
  --color-text-dim: #686d64;
  --color-border: #343832;
  --color-border-strong: #62685b;

  --font-display: "Barlow Condensed", "Arial Narrow", sans-serif;
  --font-mono: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;

  --gutter: clamp(1rem, 4.5vw, 4rem);
  --space-1: 0.25rem;
  --space-2: 0.5rem;
  --space-3: 0.75rem;
  --space-4: 1rem;
  --space-6: 1.5rem;
  --space-8: 2rem;
  --space-12: 3rem;
  --space-16: 4rem;

  --border-thin: 1px solid var(--color-border);
  --focus-ring: 2px solid var(--color-lime);
}
```

## 13. Content and Asset Direction

-   **Hero:** monochrome 3D head, wireframe sculpture, abstract neural
    object, or dark digital scan.
-   **Project thumbnails:** four visually distinct
    compositions---code/dashboard, neural network, silhouette in a
    digital corridor, and abstract grid/globe.
-   **World map:** subdued monochrome map with a tiny lime node marker.
-   **Textures:** low-opacity grain, scanlines, glitch displacement,
    pixel fragments, and thin grid overlays.
-   Keep decorative textures behind content and low enough in contrast
    that text remains readable.
-   Prefer original or properly licensed assets. If the exact hero image
    is unavailable, create a coherent abstract substitute rather than
    using unrelated stock photography.

## 14. Do / Don't Checklist

### Do

-   Preserve the black/off-white/lime palette.
-   Use uppercase condensed headings and monospaced interface labels.
-   Build the page from clearly bordered modular sections.
-   Use small section numbers and technical microcopy consistently.
-   Make the hero visual a major focal point.
-   Keep all interactions functional, accessible, and responsive.
-   Use lime as a deliberate signal for actions and active states.

### Don't

-   Add gradients, glass panels, soft shadows, or rounded pill buttons
    by default.
-   Use lime for every element.
-   Overload the page with random glitch effects or unreadable
    microtext.
-   fake real-time system metrics or successful form submissions.
-   leave buttons without destinations or interactions.
-   let decorative overlays cover important content.
-   treat the desktop screenshot as the mobile layout.

## 15. Definition of Done

The implementation is ready for review when:

-   [ ] The page follows the six-part structure: navigation, hero,
    principles, work, lower panels, footer.
-   [ ] Color, typography, borders, and spacing are consistent with this
    specification.
-   [ ] Desktop, tablet, and mobile layouts have been tested.
-   [ ] There is no horizontal overflow at narrow widths.
-   [ ] Keyboard focus and reduced-motion preferences work.
-   [ ] Buttons, navigation, project cards, and forms have honest,
    functional behavior.
-   [ ] Images are optimized and have appropriate alternative text.
-   [ ] No fake system metrics, dead links, or deceptive success states
    remain.
-   [ ] The visual feels like a deliberate cyber-brutalist interface,
    not a generic template.

------------------------------------------------------------------------

**Implementation instruction for the coding agent:** Use this document
as the source of truth for visual design and UX. Inspect the existing
codebase before changing frameworks or replacing files. Reuse the
project's current stack unless there is a clear technical reason not to.
Implement the complete responsive page, then validate the major
breakpoints, keyboard interaction, and form states. Match the
reference's visual character while keeping content, assets, and
functionality production-ready.
