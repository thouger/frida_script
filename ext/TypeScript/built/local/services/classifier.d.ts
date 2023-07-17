import { __String, CancellationToken, Classifications, ClassifiedSpan, Classifier, SourceFile, TextSpan, TypeChecker } from "./_namespaces/ts";
/** The classifier is used for syntactic highlighting in editors via the TSServer */
export declare function createClassifier(): Classifier;
/** @internal */
export declare function getSemanticClassifications(typeChecker: TypeChecker, cancellationToken: CancellationToken, sourceFile: SourceFile, classifiableNames: ReadonlySet<__String>, span: TextSpan): ClassifiedSpan[];
/** @internal */
export declare function getEncodedSemanticClassifications(typeChecker: TypeChecker, cancellationToken: CancellationToken, sourceFile: SourceFile, classifiableNames: ReadonlySet<__String>, span: TextSpan): Classifications;
/** @internal */
export declare function getSyntacticClassifications(cancellationToken: CancellationToken, sourceFile: SourceFile, span: TextSpan): ClassifiedSpan[];
/** @internal */
export declare function getEncodedSyntacticClassifications(cancellationToken: CancellationToken, sourceFile: SourceFile, span: TextSpan): Classifications;
//# sourceMappingURL=classifier.d.ts.map