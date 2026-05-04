import tailwind from 'bun-plugin-tailwind'
import { rm } from 'node:fs/promises'

await rm('./dist', { force: true, recursive: true })

const result = await Bun.build({
  entrypoints: ['./index.html'],
  compile: true,
  target: 'browser',
  outdir: './dist',
  minify: true,
  plugins: [tailwind],
})

if (!result.success) {
  for (const log of result.logs) {
    console.error(log)
  }
  process.exit(1)
}
