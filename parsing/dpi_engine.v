`timescale 1ns / 1ps

// ============================================================================
// Module: dpi_engine
// Description: Synthesizable Hardware Deep Packet Inspection (DPI) Core.
//              Consumes ONLY parsed payload stream and port metadata from
//              packet_parser_top. Uses a pipelined sliding shift register
//              and parallel combinational comparators to identify protocol
//              headers and malicious signatures.
// ============================================================================

module dpi_engine (
    input  wire        clk,
    input  wire        rst_n,
    
    // Parsed payload stream from packet parser
    input  wire        payload_valid,
    input  wire [7:0]  payload_data_in,
    input  wire        s_axis_tlast,
    
    // Transport layer metadata (min of src/dst port to determine protocol)
    input  wire [15:0] transport_port,
    
    // Hardware DPI Outputs
    output reg         dpi_match,
    output reg  [7:0]  dpi_rule_id,
    output reg  [15:0] dpi_match_offset
);

    // 64-bit sliding shift register
    reg [63:0] shift_reg;
    reg [15:0] payload_byte_cnt;

    // Shift in new payload byte combinationally
    wire [63:0] next_shift_reg = {shift_reg[55:0], payload_data_in};

    // Signature Definitions
    // Rule 1: HTTP GET      ("GET ") -> 32'h47455420
    // Rule 2: HTTP POST     ("POST") -> 32'h504F5354
    // Rule 3: HTTP Response ("HTTP") -> 32'h48545450
    // Rule 4: TLS Client Hello prefix (Record Type 0x16, Version 0x0301 or 0x0303)
    // Rule 5: Custom Malicious ("EVIL") -> 32'h4556494C
    localparam [31:0] PATTERN_HTTP_GET  = 32'h47455420;
    localparam [31:0] PATTERN_HTTP_POST = 32'h504F5354;
    localparam [31:0] PATTERN_HTTP_RESP = 32'h48545450;
    localparam [23:0] PATTERN_TLS_1_0   = 24'h160301;
    localparam [23:0] PATTERN_TLS_1_2   = 24'h160303;
    localparam [31:0] PATTERN_MAL_EVIL  = 32'h4556494C;

    // Parallel Combinational Match Detectors
    // Rule 5: Malicious "EVIL" payload signature (active across all traffic)
    wire match_r5 = (next_shift_reg[31:0] == PATTERN_MAL_EVIL) && (payload_byte_cnt >= 16'd3);

    // Rule 1: HTTP GET (active on Port 80 or unspecified port 0)
    wire match_r1 = (next_shift_reg[31:0] == PATTERN_HTTP_GET) && 
                    (payload_byte_cnt >= 16'd3) && 
                    (transport_port == 16'd80 || transport_port == 16'd0);

    // Rule 2: HTTP POST (active on Port 80 or unspecified port 0)
    wire match_r2 = (next_shift_reg[31:0] == PATTERN_HTTP_POST) && 
                    (payload_byte_cnt >= 16'd3) && 
                    (transport_port == 16'd80 || transport_port == 16'd0);

    // Rule 3: HTTP Response (active on Port 80 or unspecified port 0)
    wire match_r3 = (next_shift_reg[31:0] == PATTERN_HTTP_RESP) && 
                    (payload_byte_cnt >= 16'd3) && 
                    (transport_port == 16'd80 || transport_port == 16'd0);

    // Rule 4: TLS Client Hello Header (active on Port 443 or unspecified port 0)
    wire match_r4 = ((next_shift_reg[23:0] == PATTERN_TLS_1_0) || (next_shift_reg[23:0] == PATTERN_TLS_1_2)) && 
                    (payload_byte_cnt >= 16'd2) && 
                    (transport_port == 16'd443 || transport_port == 16'd0);

    // Sequential Shift Register & Latching Logic
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            shift_reg        <= 64'd0;
            payload_byte_cnt <= 16'd0;
            dpi_match        <= 1'b0;
            dpi_rule_id      <= 8'd0;
            dpi_match_offset <= 16'd0;
        end else begin
            if (payload_valid) begin
                shift_reg        <= next_shift_reg;
                payload_byte_cnt <= payload_byte_cnt + 1'b1;

                // Latch only the FIRST detected match until packet boundary / reset
                if (!dpi_match) begin
                    if (match_r5) begin
                        dpi_match        <= 1'b1;
                        dpi_rule_id      <= 8'd5;
                        dpi_match_offset <= payload_byte_cnt - 16'd3;
                    end else if (match_r1) begin
                        dpi_match        <= 1'b1;
                        dpi_rule_id      <= 8'd1;
                        dpi_match_offset <= payload_byte_cnt - 16'd3;
                    end else if (match_r2) begin
                        dpi_match        <= 1'b1;
                        dpi_rule_id      <= 8'd2;
                        dpi_match_offset <= payload_byte_cnt - 16'd3;
                    end else if (match_r3) begin
                        dpi_match        <= 1'b1;
                        dpi_rule_id      <= 8'd3;
                        dpi_match_offset <= payload_byte_cnt - 16'd3;
                    end else if (match_r4) begin
                        dpi_match        <= 1'b1;
                        dpi_rule_id      <= 8'd4;
                        dpi_match_offset <= payload_byte_cnt - 16'd2;
                    end
                end
            end
        end
    end

endmodule
