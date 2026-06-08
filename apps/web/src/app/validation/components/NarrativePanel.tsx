"use client";

import { copyText } from '@/lib/clipboard'
import { Copy } from "lucide-react";
import type { FusionResult } from "../lib/types";

interface NarrativePanelProps {
  result: FusionResult | null;
}

function splitNarrative(text: string) {
  return text
    .split(/\n{2,}/)
    .map((section) => section.trim())
    .filter(Boolean);
}

export default function NarrativePanel({ result }: NarrativePanelProps) {
  const narrative = result?.red_team_narrative ?? "";
  const sections = splitNarrative(narrative);

  if (!narrative) {
    return (
      <div className="text-center py-16 text-gray-600 text-sm">
        Run a module to generate a red team narrative.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4 print:bg-white print:text-black">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-bold text-white print:text-black">Red Team Narrative</h2>
        <button
          type="button"
          onClick={() => copyText(narrative)}
          className="flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-2.5 py-1.5 text-xs text-gray-300 hover:text-white"
        >
          <Copy className="h-3.5 w-3.5" />
          Copy
        </button>
      </div>

      <article className="rounded-lg border border-white/10 bg-white/[0.04] p-5 print:border-gray-300 print:bg-white">
        {sections.map((section, index) => {
          const lines = section.split("\n").map((line) => line.trimEnd());
          const first = lines[0] ?? "";
          const isHeading = first === first.toUpperCase() && first.length < 80;

          return (
            <section key={index} className="mb-5 last:mb-0">
              {isHeading ? (
                <>
                  <h3 className="mb-2 text-sm font-bold tracking-normal text-white print:text-black">{first}</h3>
                  <div className="space-y-1">
                    {lines.slice(1).map((line, lineIndex) => (
                      <p key={lineIndex} className="text-sm leading-6 text-gray-300 print:text-gray-800">
                        {line}
                      </p>
                    ))}
                  </div>
                </>
              ) : (
                <pre className="whitespace-pre-wrap font-sans text-sm leading-6 text-gray-300 print:text-gray-800">
                  {section}
                </pre>
              )}
            </section>
          );
        })}
      </article>
    </div>
  );
}
