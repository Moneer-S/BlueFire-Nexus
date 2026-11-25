// Free text of a recording, such as a step's command or what it printed: each
// direction mark, embedding, override or isolate it holds is shown as its code
// in a small tag, and never applied, so it cannot reorder what is on screen.

import { markCode, markParts } from "./format";

export function FreeText({ text }: { text: string }) {
  const parts = markParts(text);
  if (parts.length === 1 && parts[0]?.mark === false) return <>{text}</>;
  return (
    <>
      {parts.map((part, index) =>
        part.mark ? (
          <span key={index} className="lv-mark" title={`A direction character in the recording's text, ${markCode(part.text)}, shown here and not applied`}>
            {markCode(part.text)}
          </span>
        ) : (
          <span key={index}>{part.text}</span>
        ),
      )}
    </>
  );
}
