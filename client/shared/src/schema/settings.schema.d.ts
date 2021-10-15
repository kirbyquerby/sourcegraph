/* tslint:disable */
/**
 * This file was automatically generated by json-schema-to-typescript.
 * DO NOT MODIFY IT BY HAND. Instead, modify the source JSONSchema file,
 * and run json-schema-to-typescript to regenerate this file.
 */

/**
 * Configuration settings for users and organizations on Sourcegraph.
 */
export interface Settings {
  experimentalFeatures?: SettingsExperimentalFeatures;
  /**
   * DEPRECATED: Saved search queries
   */
  "search.savedQueries"?: {
    /**
     * Unique key for this query in this file
     */
    key: string;
    /**
     * Description of this saved query
     */
    description: string;
    /**
     * Query string
     */
    query: string;
    /**
     * DEPRECATED: saved searches are no longer shown on the homepage. This will be removed in a future release.
     */
    showOnHomepage?: boolean;
    /**
     * Notify the owner of this configuration file when new results are available
     */
    notify?: boolean;
    /**
     * Notify Slack via the organization's Slack webhook URL when new results are available
     */
    notifySlack?: boolean;
  }[];
  /**
   * Enables globbing for supported field values
   */
  "search.globbing"?: boolean;
  /**
   * Predefined search snippets that can be appended to any search (also known as search scopes)
   */
  "search.scopes"?: SearchScope[];
  /**
   * DEPRECATED: Use search contexts instead.
   *
   * Named groups of repositories that can be referenced in a search query using the `repogroup:` operator. The list can contain string literals (to include single repositories) and JSON objects with a "regex" field (to include all repositories matching the regular expression). Retrieving repogroups via the GQL interface will currently exclude repositories matched by regex patterns. #14208.
   */
  "search.repositoryGroups"?: {
    [k: string]: (
      | {
          [k: string]: unknown;
        }
      | string
    )[];
  };
  /**
   * A list of search.repositoryGroups that have auto-indexing enabled.
   */
  "codeIntelligence.autoIndexRepositoryGroups"?: string[];
  /**
   * Up to this number of repos are auto indexed automatically. Ordered by star count.
   */
  "codeIntelligence.autoIndexPopularRepoLimit"?: number;
  /**
   * The default number of lines to show as context below and above search results. Default is 1.
   */
  "search.contextLines"?: number;
  /**
   * The default pattern type (literal or regexp) that search queries will be intepreted as.
   */
  "search.defaultPatternType"?: string;
  /**
   * Whether query patterns are treated case sensitively. Patterns are case insensitive by default.
   */
  "search.defaultCaseSensitive"?: boolean;
  /**
   * Whether searches should include searching forked repositories.
   */
  "search.includeForks"?: boolean;
  /**
   * Whether searches should include searching archived repositories.
   */
  "search.includeArchived"?: boolean;
  /**
   * Links that should be accessible quickly from the home and search pages.
   */
  quicklinks?: QuickLink[];
  /**
   * DEPRECATED: Use `notices` instead.
   *
   * An array (often with just one element) of messages to display at the top of all pages, including for unauthenticated users. Users may dismiss a message (and any message with the same string value will remain dismissed for the user).
   *
   * Markdown formatting is supported.
   *
   * Usually this setting is used in global and organization settings. If set in user settings, the message will only be displayed to that user. (This is useful for testing the correctness of the message's Markdown formatting.)
   *
   * MOTD stands for "message of the day" (which is the conventional Unix name for this type of message).
   */
  motd?: string[];
  /**
   * Custom informational messages to display to users at specific locations in the Sourcegraph user interface.
   *
   * Usually this setting is used in global and organization settings. If set in user settings, the message will only be displayed to that single user.
   */
  notices?: Notice[];
  /**
   * Whether to show alerts for patch version updates. Alerts for major and minor version updates will always be shown.
   */
  "alerts.showPatchUpdates"?: boolean;
  /**
   * Disables observability-related site alert banners.
   */
  "alerts.hideObservabilitySiteAlerts"?: boolean;
  /**
   * What in-app messaging to use around availability of Sourcegraph's code intelligence on code hosts. If the native code host integration is installed, this should be set to "native-integration" and users won't need to install the Sourcegraph browser extension to get code intelligence on code hosts.
   */
  "alerts.codeHostIntegrationMessaging"?: "browser-extension" | "native-integration";
  /**
   * The Sourcegraph extensions to use. Enable an extension by adding a property `"my/extension": true` (where `my/extension` is the extension ID). Override a previously enabled extension and disable it by setting its value to `false`.
   */
  extensions?: {
    /**
     * `true` to enable the extension, `false` to disable the extension (if it was previously enabled)
     */
    [k: string]: boolean;
  };
  /**
   * The Sourcegraph extensions, by ID (e.g. `my/extension`), whose logs should be visible in the console.
   */
  "extensions.activeLoggers"?: string[];
  /**
   * Whether to use the code host's native hover tooltips when they exist (GitHub's jump-to-definition tooltips, for example).
   */
  "codeHost.useNativeTooltips"?: boolean;
  /**
   * REMOVED. Previously, when active, any uppercase characters in the pattern will make the entire query case-sensitive.
   */
  "search.uppercase"?: boolean;
  /**
   * REMOVED. Previously, a flag to enable and/or-expressions in queries as an aid transition to new language features in versions <= 3.24.0.
   */
  "search.migrateParser"?: boolean;
  /**
   * Disable search suggestions below the search bar when constructing queries. Defaults to false.
   */
  "search.hideSuggestions"?: boolean;
  "insights.displayLocation.insightsPage"?: boolean;
  "insights.displayLocation.directory"?: boolean;
  "insights.displayLocation.homepage"?: boolean;
  /**
   * EXPERIMENTAL: Code Insights
   */
  insights?: Insight[];
  /**
   * EXPERIMENTAL: Backend-based Code Insights
   */
  "insights.allrepos"?: {
    [k: string]: BackendInsight;
  };
  /**
   * EXPERIMENTAL: Code Insights Dashboards
   */
  "insights.dashboards"?: {
    [k: string]: InsightDashboard;
  };
  [k: string]: unknown;
}
/**
 * Experimental features to enable or disable. Features that are now enabled by default are marked as deprecated.
 */
export interface SettingsExperimentalFeatures {
  /**
   * Enables code insights on directory pages.
   */
  codeInsights?: boolean;
  /**
   * DEPRECATED: Enables the experimental ability to run an insight over all repositories on the instance.
   */
  codeInsightsAllRepos?: boolean;
  /**
   * Enables code monitoring.
   */
  codeMonitoring?: boolean;
  /**
   * Enables API documentation.
   */
  apiDocs?: boolean;
  /**
   * Enables the 'Send test email' debugging button for code monitoring.
   */
  showCodeMonitoringTestEmailButton?: boolean;
  /**
   * Enables a button on the search results page that shows language statistics about the results for a search query.
   */
  searchStats?: boolean;
  /**
   * DEPRECATED: This feature is now permanently enabled. Enables streaming search support.
   */
  searchStreaming?: boolean;
  /**
   * DEPRECATED: This feature is now permanently enabled. Enables displaying the copy query button in the search bar when hovering over the global navigation bar.
   */
  copyQueryButton?: boolean;
  /**
   * Enables the repository group homepage
   */
  showRepogroupHomepage?: boolean;
  /**
   * Enables the onboarding tour.
   */
  showOnboardingTour?: boolean;
  /**
   * Enables the search context dropdown.
   */
  showSearchContext?: boolean;
  /**
   * Enables search context management.
   */
  showSearchContextManagement?: boolean;
  /**
   * Enabled the homepage panels in the Enterprise homepage
   */
  showEnterpriseHomePanels?: boolean;
  /**
   * Enables the multiline search console at search/console
   */
  showMultilineSearchConsole?: boolean;
  /**
   * Enables the search notebook at search/notebook
   */
  showSearchNotebook?: boolean;
  /**
   * REMOVED. Previously, enabled the search query builder page. This page has been removed.
   */
  showQueryBuilder?: boolean;
  /**
   * REMOVED. Previously, added more syntax highlighting and hovers for queries in the web app. This behavior is active by default now.
   */
  enableSmartQuery?: boolean;
  /**
   * Enables optimized search result loading (syntax highlighting / file contents fetching)
   */
  enableFastResultLoading?: boolean;
  /**
   * Enables fuzzy finder with keyboard shortcut `t`.
   */
  fuzzyFinder?: boolean;
  /**
   * The maximum number of files a repo can have to use case-insensitive fuzzy finding
   */
  fuzzyFinderCaseInsensitiveFileCountThreshold?: number;
  /**
   * Whether the search bar should select completion suggestions when pressing enter
   */
  acceptSearchSuggestionOnEnter?: boolean;
  /**
   * Enables/disables the Batch Changes server side execution feature.
   */
  batchChangesExecution?: boolean;
}
export interface SearchScope {
  /**
   * The human-readable name for this search scope
   */
  name: string;
  /**
   * The query string of this search scope
   */
  value: string;
}
export interface QuickLink {
  /**
   * The human-readable name for this quick link
   */
  name: string;
  /**
   * The URL of this quick link (absolute or relative)
   */
  url: string;
  /**
   * A description for this quick link
   */
  description?: string;
}
export interface Notice {
  /**
   * The message to display. Markdown formatting is supported.
   */
  message: string;
  /**
   * The location where this notice is shown: "top" for the top of every page, "home" for the homepage.
   */
  location: "top" | "home";
  /**
   * Whether this notice can be dismissed (closed) by the user.
   */
  dismissible?: boolean;
  [k: string]: unknown;
}
export interface Insight {
  /**
   * The short title of this insight
   */
  title: string;
  /**
   * The description of this insight
   */
  description: string;
  /**
   * Series of data to show for this insight
   */
  series: InsightSeries[];
  /**
   * A globally  unique identifier for this insight.
   */
  id: string;
}
export interface InsightSeries {
  /**
   * The label to use for the series in the graph.
   */
  label: string;
  /**
   * Performs a search query and shows the number of results returned.
   */
  repositoriesList?: unknown[];
  /**
   * Performs a search query and shows the number of results returned.
   */
  search?: string;
  /**
   * (not yet supported) Fetch data from a webhook URL.
   */
  webhook?: string;
}
export interface BackendInsight {
  /**
   * The short title of this insight
   */
  title: string;
  /**
   * The description of this insight
   */
  description?: string;
  /**
   * Each query will be represented by one line on the chart.
   */
  series: BackendInsightSeries[];
  filters?: InsightFilters;
  [k: string]: unknown;
}
export interface BackendInsightSeries {
  /**
   * The name to use for the series in the graph.
   */
  name: string;
  /**
   * Performs a search query and shows the number of results returned.
   */
  query: string;
  /**
   * The color of the line for the series.
   */
  stroke?: string;
}
/**
 * Performs a filter
 */
export interface InsightFilters {
  includeRepoRegexp: string;
  excludeRepoRegexp: string;
  repositories?: string[];
  [k: string]: unknown;
}
export interface InsightDashboard {
  /**
   * Title of the dashboard.
   */
  title: string;
  id: string;
  /**
   * Insights ids that will be included in the dashboard.
   */
  insightIds?: string[];
  [k: string]: unknown;
}
