import pandas as pd
import numpy as np

def analyze_traffic_history(packets):
    """
    Performs data science analysis on lists of captured packets using Pandas and NumPy.
    Extracts time-series aggregations, conversational flow matrices, protocol byte volumes,
    and statistical summaries of packet lengths.
    """
    if not packets:
        return {
            'packet_count': 0,
            'conversations': [],
            'protocol_volumes': {},
            'length_stats': {
                'min': 0, 'max': 0, 'mean': 0, 'median': 0, 'std': 0, 'p25': 0, 'p75': 0
            },
            'timeline_series': []
        }
        
    # Load packets into a Pandas DataFrame
    df = pd.DataFrame(packets)
    
    # Fill in fallback data if columns are empty/missing
    if 'length' not in df.columns:
        df['length'] = 0
    if 'protocol' not in df.columns:
        df['protocol'] = 'Other'
    if 'timestamp' not in df.columns:
        df['timestamp'] = pd.Timestamp.now().isoformat()
        
    # Standardize column types
    df['length'] = pd.to_numeric(df['length'], errors='coerce').fillna(0).astype(int)
    
    # 1. Packet Length Statistical Summary using NumPy
    lengths = df['length'].values
    length_stats = {
        'min': int(np.min(lengths)),
        'max': int(np.max(lengths)),
        'mean': float(round(np.mean(lengths), 2)),
        'median': float(round(np.median(lengths), 2)),
        'std': float(round(np.std(lengths), 2)) if len(lengths) > 1 else 0.0,
        'p25': float(round(np.percentile(lengths, 25), 2)),
        'p75': float(round(np.percentile(lengths, 75), 2))
    }
    
    # 2. Conversation Flow Matrix
    # Group by src_ip and dst_ip to find communicating endpoints
    conv_df = df.groupby(['src_ip', 'dst_ip']).agg(
        packets=('length', 'count'),
        bytes=('length', 'sum')
    ).reset_index()
    # Sort by bytes transferred and grab top 10 conversations
    conv_df = conv_df.sort_values(by='bytes', ascending=False).head(10)
    conversations = conv_df.to_dict(orient='records')
    
    # 3. Protocol Byte Volumes
    proto_vol_df = df.groupby('protocol')['length'].sum().reset_index()
    protocol_volumes = dict(zip(proto_vol_df['protocol'], proto_vol_df['length']))
    
    # 4. Resampled Timeline Metrics
    try:
        # Convert timestamp to DatetimeIndex
        df['dt'] = pd.to_datetime(df['timestamp'])
        ts_df = df.set_index('dt')
        
        # Calculate overall capture duration in seconds to choose resampling scale
        time_span = (ts_df.index.max() - ts_df.index.min()).total_seconds() if len(ts_df) > 1 else 0
        
        if time_span > 600:
            resample_rule = '10s'
        elif time_span > 120:
            resample_rule = '5s'
        else:
            resample_rule = '1s'
            
        timeline = ts_df.resample(resample_rule).agg(
            packets=('length', 'count'),
            bytes=('length', 'sum')
        ).fillna(0)
        
        timeline_series = []
        for dt, row in timeline.iterrows():
            timeline_series.append({
                'time': dt.strftime('%H:%M:%S'),
                'packets': int(row['packets']),
                'bytes': int(row['bytes'])
            })
    except Exception:
        timeline_series = []
        
    return {
        'packet_count': len(df),
        'conversations': conversations,
        'protocol_volumes': protocol_volumes,
        'length_stats': length_stats,
        'timeline_series': timeline_series
    }
