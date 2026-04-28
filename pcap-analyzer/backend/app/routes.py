import os
import uuid
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, Optional
from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from config import UPLOAD_FOLDER, ALLOWED_EXTENSIONS, MAX_CONTENT_LENGTH
from app.parser import PCAPParser
from app.analyzer import analyze_pcap
from app.geolocation import analyze_geolocation
from app.report_generator import generate_pdf_report

bp = Blueprint('api', __name__, url_prefix='/api')

# Session storage: {session_id: {"df": DataFrame, "filename": str, "created_at": datetime}}
session_data: Dict[str, Dict[str, Any]] = {}


def cleanup_old_sessions():
    cutoff = datetime.now() - timedelta(hours=1)
    expired = [
        sid for sid, data in session_data.items()
        if data.get("created_at", datetime.now()) < cutoff
    ]
    for sid in expired:
        del session_data[sid]
    return len(expired)


def allowed_file(filename: str) -> bool:
    
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@bp.route('/health', methods=['GET'])
def health_check() -> Tuple[Dict[str, str], int]:
    
    return jsonify({
        "status": "ok",
        "message": "Backend is running"
    }), 200


@bp.route('/upload', methods=['POST'])
def upload_file() -> Tuple[Dict[str, Any], int]:
   
    # Check if file is present in request
    if 'file' not in request.files:
        return jsonify({
            "error": "No file provided in request"
        }), 400
    
    file = request.files['file']
    
    # Check if file was actually selected
    if file.filename == '':
        return jsonify({
            "error": "No file selected"
        }), 400
    
    # Check if file extension is allowed
    if not allowed_file(file.filename):
        return jsonify({
            "error": f"File type not allowed. Allowed extensions: {', '.join(ALLOWED_EXTENSIONS)}"
        }), 400
    
    try:
        # Get file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)  # Reset file pointer
        
        # Check if file is empty
        if file_size == 0:
            return jsonify({
                "error": "File is empty"
            }), 400
        
        # Check if file size exceeds limit
        if file_size > MAX_CONTENT_LENGTH:
            max_size_mb = MAX_CONTENT_LENGTH / (1024 * 1024)
            file_size_mb = file_size / (1024 * 1024)
            return jsonify({
                "error": f"File size ({file_size_mb:.2f} MB) exceeds maximum allowed size ({max_size_mb:.0f} MB). Please upload a smaller file."
            }), 413
        
        # Generate secure filename
        original_filename = secure_filename(file.filename)
        # Generate unique session ID
        session_id = str(uuid.uuid4())
        
        # Create filename with session ID prefix to avoid conflicts
        file_extension = original_filename.rsplit('.', 1)[1].lower()
        secure_name = f"{session_id}_{original_filename}"
        
        # Save file to uploads folder
        file_path = Path(UPLOAD_FOLDER) / secure_name
        file.save(str(file_path))
        
        # Verify file was saved successfully
        if not file_path.exists():
            return jsonify({
                "error": "Failed to save file"
            }), 500
        
        # Parse the PCAP file
        try:
            parser = PCAPParser(str(file_path))
            df = parser.parse()
            
            # Generate summary
            summary = parser.get_summary(df)
            
            # Run advanced analysis
            try:
                analysis = analyze_pcap(df)
            except Exception as e:
                # If analysis fails, continue without it
                analysis = {"error": str(e), "traffic": {}, "tcp": {}}
            
            # Run geolocation analysis
            try:
                geolocation = analyze_geolocation(df)
            except Exception as e:
                geolocation = {
                    "available": False,
                    "error": str(e),
                    "total_unique_ips": 0,
                    "country_distribution": [],
                    "connection_lines": [],
                    "src_map_points": [],
                    "dst_map_points": []
                }
            
            # Get sample packets (first 10)
            sample_packets = df.head(10).to_dict('records')
            # Convert numpy types to native Python types for JSON serialization
            for packet in sample_packets:
                for key, value in packet.items():
                    if hasattr(value, 'item'):  # numpy scalar
                        packet[key] = value.item()
                    elif hasattr(value, 'isoformat'):  # datetime
                        packet[key] = value.isoformat()
                    elif value is None or (isinstance(value, float) and pd.isna(value)):
                        packet[key] = None
            
            # Store DataFrame in memory with timestamp (include summary, analysis, geolocation for report)
            session_data[session_id] = {
                'df': df,
                'filepath': str(file_path),
                'filename': original_filename,
                'file_size': file_size,
                'summary': summary,
                'analysis': analysis,
                'geolocation': geolocation,
                'created_at': datetime.now()
            }
            
            # Cleanup old sessions periodically
            cleanup_old_sessions()
            
            return jsonify({
                "success": True,
                "message": "File uploaded and parsed successfully",
                "filename": original_filename,
                "file_size": file_size,
                "session_id": session_id,
                "parsing_complete": True,
                "summary": summary,
                "analysis": analysis,
                "geolocation": geolocation,
                "sample_packets": sample_packets
            }), 200
            
        except FileNotFoundError as e:
            return jsonify({
                "error": f"PCAP file not found: {str(e)}"
            }), 404
        
        except ValueError as e:
            return jsonify({
                "error": f"Invalid or corrupted PCAP file: {str(e)}"
            }), 400
        
        except RuntimeError as e:
            return jsonify({
                "error": str(e)
            }), 500
        
        except Exception as e:
            return jsonify({
                "error": f"Error parsing PCAP file: {str(e)}"
            }), 500
        
    except RequestEntityTooLarge:
        max_size_mb = MAX_CONTENT_LENGTH / (1024 * 1024)
        return jsonify({
            "error": f"File size exceeds maximum allowed size ({max_size_mb:.0f} MB). Please upload a smaller file."
        }), 413
    
    except OSError as e:
        return jsonify({
            "error": f"File system error: {str(e)}"
        }), 500
    
    except Exception as e:
        return jsonify({
            "error": f"An unexpected error occurred: {str(e)}"
        }), 500


@bp.errorhandler(413)
def request_entity_too_large(error: RequestEntityTooLarge) -> Tuple[Dict[str, str], int]:
    
    max_size_mb = MAX_CONTENT_LENGTH / (1024 * 1024)
    return jsonify({
        "error": f"File size exceeds maximum allowed size ({max_size_mb:.0f} MB). Please upload a smaller file."
    }), 413


@bp.route('/packets/<session_id>', methods=['GET'])
def get_packets(session_id: str) -> Tuple[Dict[str, Any], int]:
    
    # Check if session exists
    if session_id not in session_data:
        return jsonify({
            "error": f"Session {session_id} not found. File may not have been parsed yet."
        }), 404
    
    # Get pagination parameters
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=50, type=int)
    
    # Get sorting parameters
    sort_by = request.args.get('sort_by', default='timestamp', type=str)
    sort_order = request.args.get('sort_order', default='asc', type=str)
    
    # Get filter parameters
    filter_protocol = request.args.get('filter_protocol', default=None, type=str)
    filter_ip = request.args.get('filter_ip', default=None, type=str)
    
    # Validate pagination parameters
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 1
    if per_page > 100:
        per_page = 100
    
    # Validate sort_order
    if sort_order not in ['asc', 'desc']:
        sort_order = 'asc'
    
    try:
        df = session_data[session_id]['df'].copy()
        
        # Apply filters
        if filter_protocol and filter_protocol.strip():
            if 'protocol' in df.columns:
                df = df[df['protocol'].str.contains(filter_protocol, case=False, na=False)]
        
        if filter_ip and filter_ip.strip():
            if 'src_ip' in df.columns and 'dst_ip' in df.columns:
                mask = (
                    df['src_ip'].astype(str).str.contains(filter_ip, case=False, na=False) |
                    df['dst_ip'].astype(str).str.contains(filter_ip, case=False, na=False)
                )
                df = df[mask]
        
        # Apply sorting
        if sort_by in df.columns:
            ascending = sort_order == 'asc'
            df = df.sort_values(by=sort_by, ascending=ascending, na_position='last')
        elif sort_by == 'timestamp' and 'timestamp' in df.columns:
            ascending = sort_order == 'asc'
            df = df.sort_values(by='timestamp', ascending=ascending, na_position='last')
        
        # Calculate pagination
        total_packets = len(df)
        total_pages = (total_packets + per_page - 1) // per_page if total_packets > 0 else 0
        
        # Validate page number
        if page > total_pages and total_pages > 0:
            page = total_pages
        elif total_pages == 0:
            page = 1
        
        # Get paginated data
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_df = df.iloc[start_idx:end_idx]
        packets = paginated_df.to_dict('records')
        
        # Convert numpy types to native Python types for JSON serialization
        for packet in packets:
            for key, value in packet.items():
                if hasattr(value, 'item'):  # numpy scalar
                    packet[key] = value.item()
                elif hasattr(value, 'isoformat'):  # datetime
                    packet[key] = value.isoformat()
                elif value is None or (isinstance(value, float) and pd.isna(value)):
                    packet[key] = None
        
        return jsonify({
            "session_id": session_id,
            "page": page,
            "per_page": per_page,
            "total_packets": int(total_packets),
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
            "packets": packets
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": f"Error retrieving packets: {str(e)}"
        }), 500


@bp.route('/analysis/<session_id>', methods=['GET'])
def get_analysis(session_id: str) -> Tuple[Dict[str, Any], int]:
    
    # Check if session exists
    if session_id not in session_data:
        return jsonify({
            "error": f"Session {session_id} not found. File may not have been parsed yet."
        }), 404
    
    try:
        df = session_data[session_id]['df']
        
        # Run analysis
        analysis = analyze_pcap(df)
        
        return jsonify({
            "session_id": session_id,
            "analysis": analysis
        }), 200

    except Exception as e:
        return jsonify({
            "error": f"Error generating analysis: {str(e)}"
        }), 500


@bp.route('/geolocation/<session_id>', methods=['GET'])
def get_geolocation(session_id: str) -> Tuple[Dict[str, Any], int]:
   
    if session_id not in session_data:
        return jsonify({
            "error": f"Session {session_id} not found."
        }), 404
    
    try:
        df = session_data[session_id]['df']
        result = analyze_geolocation(df)
        
        return jsonify({
            "session_id": session_id,
            "geolocation": result
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": f"Error generating geolocation: {str(e)}"
        }), 500


@bp.route('/report/<session_id>/status', methods=['GET'])
def report_status(session_id: str):
    if session_id not in session_data:
        return jsonify({
            "available": False,
            "error": "Session not found"
        }), 404

    return jsonify({
        "available": True,
        "session_id": session_id
    }), 200


@bp.route('/report/<session_id>', methods=['GET'])
def generate_report(session_id: str):
   
    if session_id not in session_data:
        return jsonify({
            "error": f"Session {session_id} not found."
        }), 404

    try:
        data = session_data[session_id]
        summary = data.get('summary', {})
        analysis = data.get('analysis', {})
        geolocation = data.get('geolocation', {})
        filename = data.get('filename', 'unknown.pcap')
        file_size = data.get('file_size', 0)

        if not summary or not analysis:
            df = data['df']
            if not summary:
                summary = PCAPParser(data.get('filepath', '')).get_summary(df)
            if not analysis:
                analysis = analyze_pcap(df)
            if not geolocation or not geolocation.get('available'):
                try:
                    geolocation = analyze_geolocation(df)
                except Exception:
                    geolocation = geolocation or {
                        "available": False,
                        "total_unique_ips": 0,
                        "country_distribution": [],
                        "connection_lines": [],
                        "src_map_points": [],
                        "dst_map_points": []
                    }

        pdf_buffer = generate_pdf_report(
            filename=filename,
            summary=summary,
            analysis=analysis,
            geolocation=geolocation,
            file_size=file_size
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"PCAP_Analysis_Report_{timestamp}.pdf"

        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=report_filename
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": f"Error generating report: {str(e)}"
        }), 500


@bp.errorhandler(500)
def internal_server_error(error: Exception) -> Tuple[Dict[str, str], int]:
    
    return jsonify({
        "error": "Internal server error occurred"
    }), 500
