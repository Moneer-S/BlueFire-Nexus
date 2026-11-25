// Free text of a recording, such as a step's command or what it printed: each
// direction mark, embedding, override or isolate it holds is shown as its code
// in a small tag, and never applied, so it cannot reorder what is on screen.

import { markCode, markParts } from "./format";

export function FreeText({ text, keepHyphened = false }: { text: string; keepHyphened?: boolean }) {
  const parts = markParts(text);
  if (parts.length === 1 && parts[0]?.mark === false) return keepHyphened ? <Hyphened text={text} /> : <>{text}</>;
  return (
    <>
      {parts.map((part, index) =>
        part.mark ? (
          <span key={index} className="lv-mark" title={`A direction character in the recording's text, ${markCode(part.text)}, shown here and not applied`}>
            {markCode(part.text)}
          </span>
        ) : (
          <span key={index}>{keepHyphened ? <Hyphened text={part.text} /> : part.text}</span>
        ),
      )}
    </>
  );
}

/** Text whose hyphened words, such as "stand-in", never break at their hyphen: a sentence wraps between words. */
function Hyphened({ text }: { text: string }) {
  const pieces = text.split(/(\S+-\S+)/);
  if (pieces.length === 1) return <>{text}</>;
  return (
    <>
      {pieces.map((piece, index) =>
        index % 2 === 1 ? (
          <span key={index} className="lv-nobreak">
            {piece}
          </span>
        ) : (
          piece
        ),
      )}
    </>
  );
}
