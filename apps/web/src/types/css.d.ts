// Ambient declarations for CSS files imported as modules.
// Required because TypeScript does not have built-in types for CSS files,
// but Next.js handles CSS imports at the bundler level.
declare module "*.css" {
  const stylesheet: Record<string, string>;
  export default stylesheet;
}

// Explicit declaration for @xterm/xterm CSS package entry-point.
declare module "@xterm/xterm/css/xterm.css" {
  const stylesheet: Record<string, string>;
  export default stylesheet;
}
