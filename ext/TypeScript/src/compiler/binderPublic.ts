import {
    CompilerOptions,
    SourceFile,
} from "./_namespaces/ts";
import { bindSourceFile } from "./binder";

export function prebindSourceFile(file: SourceFile, options: CompilerOptions) {
    bindSourceFile(file, options);
    file.isPrebound = true;
}
