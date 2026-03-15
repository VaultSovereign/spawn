import manifest from "../../../manifest.json";
import OpenRouterMobileMirror from "./OpenRouterMobileMirror";

export default function App() {
  return <OpenRouterMobileMirror manifest={manifest} />;
}
