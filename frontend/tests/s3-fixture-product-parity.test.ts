import { expect, it } from "vitest";
import corpus from "../../tests_platform/fixtures/s3_fixture_product_v2.json";
import { checkedExercise, checkedReview, type S3Exercise, type S3Review } from "../src/lib/s3-access";

it.each(corpus.snapshots)("accepts the actual saved product projection: $name", snapshot => {
  const exercise = snapshot.exercise as unknown as S3Exercise;
  expect(checkedExercise(exercise, exercise.workflow_job_id)).toEqual(exercise);
  if (snapshot.review) {
    const review = snapshot.review as unknown as S3Review;
    expect(checkedReview(review, exercise.workflow_job_id, review.phase)).toEqual(review);
  }
});

it("reports removed test objects separately from the retained hardened policy", () => {
  const snapshot = corpus.snapshots.find(row => row.name === "absent_retained_policy")!;
  const exercise = checkedExercise(snapshot.exercise as unknown as S3Exercise, snapshot.exercise.workflow_job_id);
  expect(exercise.resource_disposition).toBe("removed");
  expect(exercise.policy_state).toBe("hardened");
  expect(exercise.policy_retention?.policy_state).toBe("hardened");
  expect(exercise.fixtures?.every(row => row.state === "absent")).toBe(true);
});
