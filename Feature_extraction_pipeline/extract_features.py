import argparse
from collections import Counter
import numpy as np
import pandas as pd


FEATURE_COLS = [
    "wnd_avg_goose_pkt_interval",
    "wnd_avg_goose_data_length",
    "wnd_goose_pkt_num",
    "wnd_goose_pkt_num_of_same_event",
    "wnd_goose_pkt_num_of_previous_event",
    "wnd_goose_pkt_num_of_not_previous_nor_same_event",
    "wnd_goose_num_of_all_events",
    "wnd_goose_pkt_num_of_same_sqNum",
    "wnd_goose_pkt_num_of_greater_than_current_sqNum",
    "wnd_goose_pkt_num_of_same_datSet",
    "wnd_goose_num_of_all_datSet",
]


def _require_cols(df: pd.DataFrame, cols: list[str], df_name="df") -> None:
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise ValueError(f"{df_name} is missing required columns: {missing}")


def _has_cols(df: pd.DataFrame, cols: list[str]) -> bool:
    return all(c in df.columns for c in cols)


def pick_stream_key(df: pd.DataFrame, prefer_gocbref: bool = True):
    """
    Decide which columns to group by to define a "GOOSE stream".

    Priority:
      - If prefer_gocbref and gocbRef exists and it is 1-1 w.r.t (Source, goID), use gocbRef.
      - Else if Source+goID exist, use (Source, goID).
      - Else fall back to best available:
          gocbRef, or goID, or Source, or raise.
    Returns: group_cols (list[str]), and a human-readable explanation string.
    """
    if prefer_gocbref and "gocbRef" in df.columns and _has_cols(df, ["Source", "goID"]):
        # Check if each gocbRef maps to exactly one Source and one goID
        tmp = df.groupby("gocbRef").agg(
            n_source=("Source", pd.Series.nunique),
            n_goid=("goID", pd.Series.nunique),
        )
        bad = tmp[(tmp["n_source"] > 1) | (tmp["n_goid"] > 1)]
        if bad.empty:
            return ["gocbRef"], "Using gocbRef (clean 1-to-1 mapping to Source+goID in this file)."
        else:
            # fall back
            return ["Source", "goID"], (
                f"gocbRef is NOT 1-to-1 (found {len(bad)} gocbRef values mapping to multiple Source/goID). "
                "Falling back to stream key = (Source, goID)."
            )

    if _has_cols(df, ["Source", "goID"]):
        return ["Source", "goID"], "Using stream key = (Source, goID)."

    # degrade gracefully
    if "gocbRef" in df.columns:
        return ["gocbRef"], "Using gocbRef (Source/goID missing; cannot validate)."
    if "goID" in df.columns:
        return ["goID"], "Using goID only (Source missing; weakest acceptable fallback)."
    if "Source" in df.columns:
        return ["Source"], "Using Source only (goID missing; weakest acceptable fallback)."

    raise ValueError("Cannot define stream key: need at least one of gocbRef / (Source+goID) / goID / Source.")


def compute_stream_features_lahza(g: pd.DataFrame, wnd_size: float = 2.0, trim_warmup: bool = True):
    """
    Compute Lahza Table-4 GOOSE advanced features for ONE stream.
    g must contain: EpochArrivalTime, Length, stNum, sqNum, datSet, packet_id
    Returns: features_df aligned to g rows (possibly trimmed) and the start_idx used.
    """
    g = g.sort_values("EpochArrivalTime").reset_index(drop=True)

    t = g["EpochArrivalTime"].to_numpy(dtype=float)
    length = g["Length"].to_numpy(dtype=float)
    st = g["stNum"].to_numpy()
    sq = g["sqNum"].to_numpy()
    ds = g["datSet"].to_numpy()

    n = len(g)
    if n == 0:
        return pd.DataFrame(columns=FEATURE_COLS), 0

    # Per-stream time interval (first = 0)
    time_interval = np.empty(n, dtype=float)
    time_interval[0] = 0.0
    if n > 1:
        time_interval[1:] = np.diff(t)

    ps_interval = np.concatenate(([0.0], np.cumsum(time_interval)))
    ps_length = np.concatenate(([0.0], np.cumsum(length)))

    L = 0
    c_st = Counter()
    c_sq = Counter()
    c_ds = Counter()

    avg_interval = np.zeros(n, dtype=float)
    avg_length = np.zeros(n, dtype=float)
    pkt_num = np.zeros(n, dtype=int)

    same_event = np.zeros(n, dtype=int)
    prev_event = np.zeros(n, dtype=int)
    other_event = np.zeros(n, dtype=int)
    uniq_events = np.zeros(n, dtype=int)

    same_sq = np.zeros(n, dtype=int)
    greater_sq = np.zeros(n, dtype=int)

    same_ds = np.zeros(n, dtype=int)
    uniq_ds = np.zeros(n, dtype=int)

    uniq_st_cnt = 0
    uniq_ds_cnt = 0

    def add_counter(c: Counter, v, uniq_count: int) -> int:
        if c[v] == 0:
            uniq_count += 1
        c[v] += 1
        return uniq_count

    def remove_counter(c: Counter, v, uniq_count: int) -> int:
        c[v] -= 1
        if c[v] == 0:
            uniq_count -= 1
            del c[v]
        return uniq_count

    for i in range(n):
        cutoff = t[i] - wnd_size

        # keep t >= cutoff (last wnd_size seconds)
        while L < i and t[L] < cutoff:
            uniq_st_cnt = remove_counter(c_st, st[L], uniq_st_cnt)
            uniq_ds_cnt = remove_counter(c_ds, ds[L], uniq_ds_cnt)
            c_sq[sq[L]] -= 1
            if c_sq[sq[L]] == 0:
                del c_sq[sq[L]]
            L += 1

        # include current packet in window counts
        uniq_st_cnt = add_counter(c_st, st[i], uniq_st_cnt)
        uniq_ds_cnt = add_counter(c_ds, ds[i], uniq_ds_cnt)
        c_sq[sq[i]] += 1

        window_len = i - L + 1
        pkt_num[i] = window_len

        avg_interval[i] = (ps_interval[i + 1] - ps_interval[L]) / window_len
        avg_length[i] = (ps_length[i + 1] - ps_length[L]) / window_len

        cur_st = st[i]
        prev_st = cur_st - 1
        same_event[i] = c_st.get(cur_st, 0)
        prev_event[i] = c_st.get(prev_st, 0)
        other_event[i] = window_len - same_event[i] - prev_event[i]

        uniq_events[i] = uniq_st_cnt

        cur_sq = sq[i]
        same_sq[i] = c_sq.get(cur_sq, 0)
        greater_sq[i] = sum(cnt for k, cnt in c_sq.items() if k > cur_sq)

        cur_ds = ds[i]
        same_ds[i] = c_ds.get(cur_ds, 0)
        uniq_ds[i] = uniq_ds_cnt

    features = pd.DataFrame({
        "wnd_avg_goose_pkt_interval": avg_interval,
        "wnd_avg_goose_data_length": avg_length,
        "wnd_goose_pkt_num": pkt_num,
        "wnd_goose_pkt_num_of_same_event": same_event,
        "wnd_goose_pkt_num_of_previous_event": prev_event,
        "wnd_goose_pkt_num_of_not_previous_nor_same_event": other_event,
        "wnd_goose_num_of_all_events": uniq_events,
        "wnd_goose_pkt_num_of_same_sqNum": same_sq,
        "wnd_goose_pkt_num_of_greater_than_current_sqNum": greater_sq,
        "wnd_goose_pkt_num_of_same_datSet": same_ds,
        "wnd_goose_num_of_all_datSet": uniq_ds,
    })

    start_idx = 0
    if trim_warmup:
        start_idx = int(np.searchsorted(t, t[0] + wnd_size, side="left"))
        features = features.iloc[start_idx:].reset_index(drop=True)

    return features, start_idx


def preprocess_file(in_path: str, out_path: str, wnd_size: float = 2.0, trim_warmup: bool = True):
    df = pd.read_excel(in_path)

    _require_cols(df, ["EpochArrivalTime", "Length", "stNum", "sqNum", "datSet"], "input df")

    # Stable packet id
    df = df.reset_index(drop=True)
    df["packet_id"] = df.index

    # Ensure label exists
    if "label" not in df.columns:
        df["label"] = False

    group_cols, explanation = pick_stream_key(df, prefer_gocbref=True)
    print("[stream key]", explanation)
    print("[stream key] grouping by:", group_cols)

    all_parts = []

    # groupby supports list of columns
    for key, g in df.groupby(group_cols, sort=False):
        g = g.sort_values("EpochArrivalTime").reset_index(drop=True)

        feats, start_idx = compute_stream_features_lahza(g, wnd_size=wnd_size, trim_warmup=trim_warmup)
        if len(feats) == 0:
            continue

        packet_ids = g.loc[start_idx:, "packet_id"].reset_index(drop=True)
        labels = g.loc[start_idx:, "label"].reset_index(drop=True)
        times      = g.loc[start_idx:, "EpochArrivalTime"].reset_index(drop=True)

        feats["packet_id"] = packet_ids
        feats["EpochArrivalTime"] = times
        feats["label"] = labels

        # store a single string key column for debugging / downstream splits
        # (even if group_cols is multiple columns)
        if isinstance(key, tuple):
            stream_key_str = "||".join(str(x) for x in key)
        else:
            stream_key_str = str(key)
        feats["stream_key"] = stream_key_str

        all_parts.append(feats)

    df_out = pd.concat(all_parts, ignore_index=True) if all_parts else pd.DataFrame(columns=FEATURE_COLS + ["packet_id", "stream_key", "label"])

    df_out = df_out[FEATURE_COLS + ["EpochArrivalTime", "packet_id", "stream_key", "label"]].copy()


    # sanity prints
    print("Saved:", out_path)
    print("Rows out:", len(df_out), " | Cols:", len(df_out.columns))
    if df_out["label"].notna().all():
        print("Label == 1 count:", int((df_out["label"] == 1).sum()))
        print("Label == 0 count:", int((df_out["label"] == 0).sum()))

    df_out.to_excel(out_path, index=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    ap.add_argument("--wnd", dest="wnd_size", type=float, default=2.0)
    ap.add_argument("--no-trim", dest="trim_warmup", action="store_false")
    args = ap.parse_args()

    preprocess_file(args.in_path, args.out_path, wnd_size=args.wnd_size, trim_warmup=args.trim_warmup)


if __name__ == "__main__":
    main()
