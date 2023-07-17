export type ActionSet = "action::set";
export type ActionInvalidate = "action::invalidate";
export type ActionPackageInstalled = "action::packageInstalled";
export type EventTypesRegistry = "event::typesRegistry";
export type EventBeginInstallTypes = "event::beginInstallTypes";
export type EventEndInstallTypes = "event::endInstallTypes";
export type EventInitializationFailed = "event::initializationFailed";
export type ActionWatchTypingLocations = "action::watchTypingLocations";
/** @internal */
export declare const ActionSet: ActionSet;
/** @internal */
export declare const ActionInvalidate: ActionInvalidate;
/** @internal */
export declare const ActionPackageInstalled: ActionPackageInstalled;
/** @internal */
export declare const EventTypesRegistry: EventTypesRegistry;
/** @internal */
export declare const EventBeginInstallTypes: EventBeginInstallTypes;
/** @internal */
export declare const EventEndInstallTypes: EventEndInstallTypes;
/** @internal */
export declare const EventInitializationFailed: EventInitializationFailed;
/** @internal */
export declare const ActionWatchTypingLocations: ActionWatchTypingLocations;
/** @internal */
export declare namespace Arguments {
    const GlobalCacheLocation = "--globalTypingsCacheLocation";
    const LogFile = "--logFile";
    const EnableTelemetry = "--enableTelemetry";
    const TypingSafeListLocation = "--typingSafeListLocation";
    const TypesMapLocation = "--typesMapLocation";
    /**
     * This argument specifies the location of the NPM executable.
     * typingsInstaller will run the command with `${npmLocation} install ...`.
     */
    const NpmLocation = "--npmLocation";
    /**
     * Flag indicating that the typings installer should try to validate the default npm location.
     * If the default npm is not found when this flag is enabled, fallback to `npm install`
     */
    const ValidateDefaultNpmLocation = "--validateDefaultNpmLocation";
}
/** @internal */
export declare function hasArgument(argumentName: string): boolean;
/** @internal */
export declare function findArgument(argumentName: string): string | undefined;
/** @internal */
export declare function nowString(): string;
//# sourceMappingURL=shared.d.ts.map