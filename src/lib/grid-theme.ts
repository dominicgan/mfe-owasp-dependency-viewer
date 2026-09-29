import { AllCommunityModule, colorSchemeDark, colorSchemeLight, ModuleRegistry, themeQuartz } from 'ag-grid-community'

// Registered here rather than in a component file so it happens exactly once,
// as a side effect of anything that needs a grid at all.
ModuleRegistry.registerModules([AllCommunityModule])

/**
 * The grids are themed from the same CSS variables as the rest of the app, so
 * the light/dark toggle moves them with everything else rather than leaving an
 * island of the wrong colour scheme.
 */
const quartz = themeQuartz.withParams({
  backgroundColor: 'var(--card)',
  foregroundColor: 'var(--card-foreground)',
  headerBackgroundColor: 'var(--muted)',
  headerTextColor: 'var(--muted-foreground)',
  borderColor: 'var(--border)',
  oddRowBackgroundColor: 'transparent',
  rowHoverColor: 'var(--accent)',
  selectedRowBackgroundColor: 'color-mix(in oklab, var(--primary) 12%, transparent)',
  accentColor: 'var(--ring)',
  fontFamily: 'inherit',
  fontSize: '12px',
  headerFontSize: '11px',
  headerFontWeight: 600,
  rowHeight: 38,
  headerHeight: 36,
  wrapperBorderRadius: '0px',
  borderRadius: '4px',
  cellHorizontalPadding: 10,
})

export const themeDark = quartz.withPart(colorSchemeDark)
export const themeLight = quartz.withPart(colorSchemeLight)

export function gridTheme(mode: 'dark' | 'light') {
  return mode === 'dark' ? themeDark : themeLight
}

/** Shared column behaviour: everything sortable, resizable and filterable. */
export const defaultColDef = {
  sortable: true,
  resizable: true,
  filter: true,
  cellClass: 'flex items-center',
}

export const textFilter = {
  filter: 'agTextColumnFilter',
  filterParams: { buttons: ['reset'], maxNumConditions: 1 },
}
export const numFilter = { filter: 'agNumberColumnFilter', filterParams: { buttons: ['reset'] } }
/** A low-cardinality column: same widget, but without the extra condition row. */
export const setish = { filter: 'agTextColumnFilter', filterParams: { buttons: ['reset'] } }
