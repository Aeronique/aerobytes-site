// .github/scripts/fetch-contributions.mjs
// Pulls the last year of contributions straight from GitHub's GraphQL API
// (the official source) and writes assets/data/contributions.json in the
// same shape the front-end widget expects:
//   { "total": { "lastYear": N }, "contributions": [ { date, count, level } ] }

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const USER = process.env.GH_USER || "Aeronique";
const TOKEN = process.env.GH_TOKEN;
const OUT = "assets/data/contributions.json";

if (!TOKEN) {
  console.error("Missing GH_TOKEN environment variable.");
  process.exit(1);
}

// last 365 days
const to = new Date();
const from = new Date(to.getTime() - 364 * 24 * 60 * 60 * 1000);

const QUERY = `
query($login: String!, $from: DateTime!, $to: DateTime!) {
  user(login: $login) {
    contributionsCollection(from: $from, to: $to) {
      contributionCalendar {
        totalContributions
        weeks {
          contributionDays {
            date
            contributionCount
            contributionLevel
          }
        }
      }
    }
  }
}`;

// GitHub returns quartile enums; map them to the 0-4 the widget colors by
const LEVEL = {
  NONE: 0,
  FIRST_QUARTILE: 1,
  SECOND_QUARTILE: 2,
  THIRD_QUARTILE: 3,
  FOURTH_QUARTILE: 4,
};

async function main() {
  const res = await fetch("https://api.github.com/graphql", {
    method: "POST",
    headers: {
      Authorization: `bearer ${TOKEN}`,
      "Content-Type": "application/json",
      "User-Agent": "aerobytes-activity",
    },
    body: JSON.stringify({
      query: QUERY,
      variables: { login: USER, from: from.toISOString(), to: to.toISOString() },
    }),
  });

  if (!res.ok) {
    console.error("GraphQL HTTP error:", res.status, await res.text());
    process.exit(1);
  }

  const json = await res.json();
  if (json.errors) {
    console.error("GraphQL returned errors:", JSON.stringify(json.errors));
    process.exit(1);
  }

  const cal = json?.data?.user?.contributionsCollection?.contributionCalendar;
  if (!cal || !Array.isArray(cal.weeks)) {
    console.error("No contribution calendar found in the response.");
    process.exit(1);
  }

  const contributions = [];
  for (const week of cal.weeks) {
    for (const day of week.contributionDays) {
      contributions.push({
        date: day.date,
        count: day.contributionCount,
        level: LEVEL[day.contributionLevel] ?? 0,
      });
    }
  }

  const out = { total: { lastYear: cal.totalContributions }, contributions };

  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify(out));
  console.log(`Wrote ${contributions.length} days, total ${cal.totalContributions} to ${OUT}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
